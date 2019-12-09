# password-cracker

A multithreaded password cracker.

![Application Image](password-cracker.png)

## Building

Prerequisites
- GCC
- Clang
- Make

```bash
sudo apt-get update && sudo apt-get install clang-5.0 libc++abi-dev libc++-dev git gdb valgrind graphviz imagemagick gnuplot
sudo apt-get install libncurses5-dev libncursesw5-dev
git clone https://github.com/realeigenvalue/password-cracker.git
cd password-cracker
make
./cracker2 <num_threads> < password_file.txt
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
GNU GPLv3
