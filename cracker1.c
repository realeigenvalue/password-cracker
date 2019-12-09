#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <string.h>
#include <crypt.h>
#include "cracker1.h"
#include "format.h"
#include "queue.h"
#include "utils.h"

#define max(a, b) (((a) > (b)) ? (a) : (b))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define MAX_QUEUE_SIZE (20)

pthread_mutex_t m_lock_post = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t m_lock_exit = PTHREAD_MUTEX_INITIALIZER;

extern FILE *stdin;

typedef struct _user {
	char username[64];
	char user_hash[64];
	char known_part[64];
	int prefix_length;
} user_t;

typedef struct _task {
	int (*work)(void *, int, int);
	user_t *task_data;
	int successful;
	double task_time;
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

void thread_pool_init(thread_pool_t *p, int size, Queue *task_queue);
void *get_task(void *argument);
void process_task(task_t *task, int thread_id);
int find_password(void *argument, int prefix_length, int thread_id);
task_t *convert_to_task(const char *line);
int test_hash(const char *user_hash, const char *password, int thread_id);
void task_destory(task_t *task);
void thread_pool_destory(thread_pool_t *p);

int num_recovered = 0;
int num_failed = 0;
double total_cpu_time = 0;
typedef struct crypt_data crypt_data_t;
crypt_data_t *cdata; 
	
int start(size_t thread_count) {
	// your code here
	// make sure to make thread_count threads
	double start = getTime();
	cdata = malloc(sizeof(crypt_data_t) * thread_count);
	int i = 0;
	for(i = 0; i < (int)thread_count; i++) {
		cdata[i].initialized = 0;
	}
	Queue task_queue;
	thread_pool_t thread_pool;
	Queue_init(&task_queue, MAX_QUEUE_SIZE);
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	while ((read = getline(&line, &len, stdin)) != -1) {
		Queue_push(&task_queue, convert_to_task(line));
	}
	thread_pool_init(&thread_pool, thread_count, &task_queue);
	for(i = 0; i < (int)thread_count; i++) {
		pthread_join(thread_pool.tid[i], NULL);
	}
	double end = getTime();
	double time_elapsed = end - start;
	v1_print_summary(num_recovered, num_failed, time_elapsed, total_cpu_time);
	free(cdata);
	free(line);
	Queue_destroy(&task_queue);
	thread_pool_destory(&thread_pool);
  	return 0;
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
	while(task_queue->size > 0) {
		task_t *task = (task_t *)(Queue_pull(task_queue));
		process_task(task, arg->thread_id);
	}
	return NULL;
}

task_t *convert_to_task(const char *line) {
	task_t *t = malloc(sizeof(task_t));
	user_t *u = malloc(sizeof(user_t));
	sscanf(line, "%s %s %s", u->username, u->user_hash, u->known_part);
	u->prefix_length = getPrefixLength(u->known_part);
	int i = 0;
	for(i = u->prefix_length; i < (int)strlen(u->known_part); i++) {
		u->known_part[i] = 'a';
	}
	t->work = find_password;
	t->task_data = u;
	return t;
}

void process_task(task_t *task, int thread_id) {
	user_t *u = (user_t *)(task->task_data);
	v1_print_thread_start(thread_id, u->username);

	double start = getThreadCPUTime();
	int retval = task->work(u, u->prefix_length, thread_id);
	double end = getThreadCPUTime();
	task->task_time = end - start;
	
	int result = 0;
	task->successful = 1;
	if(retval < 0) {
		result = 1;
		task->successful = 0;
		retval = abs(retval);
	}
	v1_print_thread_result(thread_id, u->username, u->known_part, retval, task->task_time, result);
	task_destory(task);
}

int find_password(void *argument, int prefix_length, int thread_id) {
	user_t *u = (user_t *)argument;
	char *str = u->known_part;
	int hashCount = 0;
  	char last_char = str[prefix_length - 1];
 	while(str[prefix_length - 1] == last_char) {
 		hashCount++;
 		if(test_hash(u->user_hash, str, thread_id)) {
 			return hashCount;
 		}
		incrementString(str);
 	}
 	return -1 * hashCount;
}

int test_hash(const char *user_hash, const char *password, int thread_id) {
	const char *hashed_password = crypt_r(password, "xx", &cdata[thread_id - 1]);
	return strcmp(user_hash, hashed_password) == 0 ? 1 : 0;
}

void task_destory(task_t *task) {
	pthread_mutex_lock(&m_lock_post);
	if(task->successful) {
		num_recovered++;
	} else {
		num_failed++;
	}
	total_cpu_time += task->task_time;
	pthread_mutex_unlock(&m_lock_post);
	free(task->task_data);
	free(task);
}

void thread_pool_destory(thread_pool_t *p) {
	free(p->tid);
	free(p->arg);
}