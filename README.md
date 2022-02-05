 
# Binary Only Thread Sanitizer

This project contains a binary only thread sanitizer based on the binary rewriting toolkit zipr.

## Compile and Run

For dependencies, apart from the ones required by zipr, this framework also uses protobuf.

To compile the thread sanitizer, you must have a fully compiled instance of zipr on your computer.
It can currently be found here: https://git.zephyr-software.com/opensrc/zipr.

After compiling zipr, clone this repository and enter it. Execute the following commands to compile it:
```
mkdir build && cd build
cmake -DZIPR_LOCATION=/path/to/your/zipr/folder ..
make
```

To execute the thread sanitizer, use the script 'thread-sanitizer.sh' created in the build folder:
```
./build/thread-sanitizer.sh /usr/bin/ls ls-sanitized
```
Note that this will create a folder with logs and other information in the current working directory.
