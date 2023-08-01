 
# Binary Only Thread Sanitizer

This project contains a binary only thread sanitizer based on the binary rewriting toolkit zipr.

## Compile and Run

For dependencies, apart from the ones required by zipr, this framework also uses protobuf.

To compile the thread sanitizer, you must have a fully compiled instance of zipr on your computer.
It can currently be found here: https://git.zephyr-software.com/opensrc/zipr. Alternatively, you may use our fork of zipr, which supports debugging symbols, which can be found here: https://anonymous.4open.science/r/zipr-debugging

After compiling zipr, clone this repository and enter it. Execute the following commands to compile it:
```
mkdir build && cd build
cmake -DZIPR_LOCATION=/path/to/your/zipr/folder ..
make
```

To run the tests that are included in this project, use
```
make check
```
in the build folder.
Running this will take up to 20 minutes.
The process can not be correctly terminated using Ctrl+C in the command line.

To run the c-testsuite, the utility TMSU has to be installed on the computer.


To execute the thread sanitizer, use the script 'thread-sanitizer.sh' created in the build folder:
```
./build/thread-sanitizer.sh /usr/bin/ls ls-sanitized
```
Note that this will create a folder with logs and other information in the current working directory.

The thread sanitizer has a number of different options that affect the generated binary.
A list and description of all options can be shown with:
```
./build/thread-sanitizer.sh --help
```
