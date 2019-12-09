#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <string.h>
#include <crypt.h>
#include "format.h"
#include "queue.h"
#include "utils.h"
#include "cracker2.h"
#include <semaphore.h>

#define MAX_QUEUE_SIZE (20)

pthread_mutex_t m_lock_run = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t m_lock_get = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t m_lock_print = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t m_lock_post = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t m_lock_barrier = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t m_lock_search = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cv_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t cv_wait_main = PTHREAD_COND_INITIALIZER;
sem_t sem;

extern FILE *stdin;

typedef struct _user {
	char username[64];
	char user_hash[64];
	char known_part[64];
	int prefix_length;
	int unknown_letter_count;
} user_t;

typedef struct _job {
	user_t *user;
	//if found result = 1, not found = result = 0;
	char *password;
	volatile int result;
	int total_time;
	int total_hashCount;
} job_t;

typedef struct _range {
	long a;
	long b;
	long increment;
} range_t;

typedef struct _task {
	int (*work)(void *, int);
	job_t *job;
	range_t range;
	//status = 0 not found looked through all, status = 1 found, status = 2 stopeed
	int status; 
	double task_time;
	char *start_password;
	int hashCount;
} task_t;

typedef struct _thread_argument {
	int thread_id;
	void *parameter;
} thread_argument_t; 

typedef struct _thread_pool {
	int threads;
	pthread_t *tid;
	thread_argument_t *arg;
} thread_pool_t;

volatile int running;
volatile int remaining;
typedef struct crypt_data crypt_data_t;
crypt_data_t *cdata; 

crypt_data_t *cdata_init(int thread_count);
job_t *convert_to_job(const char *line);
void thread_pool_init(thread_pool_t *p, int size, Queue *task_queue);
void *get_task(void *argument);
void distrubute_work(job_t *job, int thread_count, Queue *task_queue);
task_t *task_create(job_t *job, range_t range);
void process_task(task_t *task, int thread_id);
int find_password(void *argument, int thread_id);
int test_hash(const char *user_hash, const char *password, int thread_id);
void task_destory(task_t *task);
void thread_pool_destory(thread_pool_t *p);
int process_status(int status);
int is_running();
void set_running(int value);
void barrier();
void job_destroy(job_t *job);
int get_job_result(job_t *job);
void set_job_result(job_t *job, int value);

int start(size_t thread_count) {
	// TODO your code here, make sure to use thread_count!
	set_running(1);
	remaining = thread_count;
	sem_init(&sem, 0, 0);
	cdata = cdata_init(thread_count);

	Queue task_queue;
	thread_pool_t thread_pool;
	Queue_init(&task_queue, MAX_QUEUE_SIZE);
	thread_pool_init(&thread_pool, thread_count, &task_queue);
	job_t *job = NULL;

	double start = 0, end = 0, time_elapsed = 0;
	char *line = NULL; size_t len = 0; ssize_t read;
	while ((read = getline(&line, &len, stdin)) != -1) {
		start = getCPUTime();
		job = convert_to_job(line);	
		distrubute_work(job, thread_count, &task_queue);
		pthread_mutex_lock(&m_lock_barrier);
		while(remaining > 0) {
			pthread_cond_wait(&cv_wait_main, &m_lock_barrier);
		}
		pthread_mutex_unlock(&m_lock_barrier);
		end = getCPUTime();
		time_elapsed = end - start;
		v2_print_summary(job->user->username, job->password, job->total_hashCount, time_elapsed, job->total_time, job->result);
		job_destroy(job);
		remaining = thread_count;
	}
	set_running(0);
	free(cdata);
	free(line);
	Queue_destroy(&task_queue);
	thread_pool_destory(&thread_pool);
	return 0;
}

crypt_data_t *cdata_init(int thread_count) {
	crypt_data_t *cdata = malloc(sizeof(crypt_data_t) * thread_count);
	int i = 0;
	for(i = 0; i < thread_count; i++) {
		cdata[i].initialized = 0;
	}
	return cdata;
}

job_t *convert_to_job(const char *line) {
	job_t *job = malloc(sizeof(job_t));
	job->user = malloc(sizeof(user_t));
	job->password = NULL;
	job->result = 1;
	job->total_time = 0;
	job->total_hashCount = 0;
	sscanf(line, "%s %s %s", job->user->username, job->user->user_hash, job->user->known_part);
	job->user->prefix_length = getPrefixLength(job->user->known_part);
	job->user->unknown_letter_count = strlen(job->user->known_part) - job->user->prefix_length;
	return job;
}

void thread_pool_init(thread_pool_t *p, int size, Queue *task_queue) {
	p->threads = size;
	p->tid = malloc(sizeof(pthread_t) * p->threads);
	p->arg = malloc(sizeof(thread_argument_t) * p->threads);
	int i = 0;
	for(i = 0; i < p->threads; i++) {
		p->arg[i].thread_id = i + 1;
		p->arg[i].parameter = task_queue;
		pthread_create(p->tid + i, NULL, get_task, (void *)(p->arg + i));
	}
}

void *get_task(void *argument) {
	thread_argument_t *arg = (thread_argument_t *)argument;
	Queue *task_queue = (Queue *)(arg->parameter);
	while(is_running()) {
		pthread_mutex_lock(&m_lock_get);
		while(task_queue->size == 0) {
			pthread_cond_wait(&cv_empty, &m_lock_get);
		}
		task_t *task = (task_t *)(Queue_pull(task_queue));
		pthread_mutex_unlock(&m_lock_get);
		process_task(task, arg->thread_id);
		barrier();
	}
	return NULL;
}

void distrubute_work(job_t *job, int thread_count, Queue *task_queue) {
	int i = 0;
	for(i = 0; i < thread_count; i++) {
		range_t range;
		getSubrange(job->user->unknown_letter_count, (size_t)thread_count, i + 1, &range.a, &range.increment);
		range.b = (range.a + range.increment) - 1;
		Queue_push(task_queue, task_create(job, range));
	}
	pthread_cond_broadcast(&cv_empty);
}

task_t *task_create(job_t *job, range_t range) {
	task_t *t = malloc(sizeof(task_t));
	t->work = find_password;
	t->job = job;
	t->range = range;
	t->status = 0;
	t->task_time = 0;
	t->start_password = strdup(job->user->known_part);
	setStringPosition(t->start_password + job->user->prefix_length, range.a);
	t->hashCount = 0;
	return t;
}

void process_task(task_t *task, int thread_id) {
	user_t *user = task->job->user;
	range_t *range = &(task->range);
	v2_print_thread_start(thread_id, user->username, range->a, task->start_password);
	double start = getThreadCPUTime();
	task->hashCount = task->work(task, thread_id);
	double end = getThreadCPUTime();
	task->task_time = end - start;
	int result = process_status(task->status);
	pthread_mutex_lock(&m_lock_print);
	v2_print_thread_result(thread_id, task->hashCount, result);
	pthread_mutex_unlock(&m_lock_print);
	task_destory(task);
}

int find_password(void *argument, int thread_id) {
	task_t *task = (task_t *)argument;
	user_t *user = task->job->user;
	range_t *range = &(task->range);
	char *str = task->start_password;
	int i = 0, hashCount = 0;
	for(i = range->a; i <= range->b; i++) {
		if(get_job_result(task->job) == 0) {
			task->status = 2;
			return hashCount;
		}
		if(test_hash(user->user_hash, str, thread_id)) {
		   task->job->password = strdup(str);
		   set_job_result(task->job, 0);
		   task->status = 1;
		   return hashCount + 1;
		}
		incrementString(str);
		hashCount++;
	}
	task->status = 0;
	return hashCount;
}

int test_hash(const char *user_hash, const char *password, int thread_id) {
	const char *hashed_password = crypt_r(password, "xx", &cdata[thread_id - 1]);
	return strcmp(user_hash, hashed_password) == 0 ? 1 : 0;
}

void task_destory(task_t *task) {
	pthread_mutex_lock(&m_lock_post);
	task->job->total_time += task->task_time;
	task->job->total_hashCount += task->hashCount;
	pthread_mutex_unlock(&m_lock_post);
	free(task->start_password);
	free(task);
}

void thread_pool_destory(thread_pool_t *p) {
	free(p->tid);
	free(p->arg);
}

int process_status(int status) {
	int result = 0;
	if(status == 0) {
		result = 2;
	} else if(status == 1) {
		result = 0;
	} else if(status == 2) {
		result = 1;
	}
	return result;
}

int is_running() {
	pthread_mutex_lock(&m_lock_run);
	int result = running;
	pthread_mutex_unlock(&m_lock_run);
	return result;
}

void set_running(int value) {
	pthread_mutex_lock(&m_lock_run);
	running = value;
	pthread_mutex_unlock(&m_lock_run);
}

void barrier() {
	pthread_mutex_lock(&m_lock_barrier);
	remaining--;
	if(remaining == 0) {
		pthread_cond_signal(&cv_wait_main);
	}
	pthread_mutex_unlock(&m_lock_barrier);
	if(remaining) {
		sem_wait(&sem);
	}
	sem_post(&sem);
}

void job_destroy(job_t *job) {
	free(job->user);
	free(job->password);
	free(job);
}

int get_job_result(job_t *job) {
	pthread_mutex_lock(&m_lock_search);
	int result = job->result;
	pthread_mutex_unlock(&m_lock_search);
	return result;
}

void set_job_result(job_t *job, int value) {
	pthread_mutex_lock(&m_lock_search);
	job->result = value;
	pthread_mutex_unlock(&m_lock_search);
}