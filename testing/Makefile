SHELL := /bin/bash

all: test.san test.fuzz test.zaf test.sanzaf

test.sanzaf: test
	@echo "BUILD SAN-ZAFL"
	./zafl.sh ./test ./test.sanzaf -T
	cp ./test.sanzaf ./fuzzing/test.sanzaf
	@echo ""
	@echo ""
	@echo "--------------------------------"

test.zaf: test
	@echo "BUILD ZAFL"
	./zafl.sh ./test ./test.zaf
	cp ./test.zaf ./fuzzing/test.zaf
	@echo ""
	@echo ""
	@echo "--------------------------------"

test.fuzz: test
	@echo "BUILD FUZZ"
	afl-g++ -std=c++17 -g test.cpp -lpthread -o test.fuzz
	cp ./test.fuzz ./fuzzing/test.fuzz
	@echo ""
	@echo ""
	@echo "--------------------------------"

test.san: test
	@echo "BUILD SANITIZED"
	../build/thread-sanitizer.sh ./test ./test.san
	@echo ""
	@echo ""
	@echo "--------------------------------"

test: clean
	@echo "BUILD TEST"
	g++ -std=c++17 -g test.cpp -lpthread -o test
	cp ./test ./fuzzing/test
	@echo ""
	@echo ""
	@echo "--------------------------------"

clean:
	@echo "CLEAN"
	rm -f ./test
	rm -f ./fuzzing/test
	rm -f ./test.zaf
	rm -f ./fuzzing/test.zaf
	rm -f ./test.fuzz
	rm -f ./fuzzing/test.fuzz
	rm -f ./test.san
	rm -f ./test.san.instrinfo
	rm -f ./test.sanzaf
	rm -f ./fuzzing/test.sanzaf
	rm -rf ./tsan_temp.test.*
	rm -rf ./peasoup_executable_directory.test*
	# cd ~/Desktop/CISPA/Projekte/zipr && ./set_env_vars && pwd
	@echo ""
	@echo ""
	@echo "--------------------------------"