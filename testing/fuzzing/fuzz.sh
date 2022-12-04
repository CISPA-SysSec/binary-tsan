export AFL_SKIP_BIN_CHECK=1
export TSAN_OPTIONS=abort_on_error=1:symbolize=0

target=""

if [ $# -eq 0 ]
then
    target="./test.sanzaf"
else
    target=$1
fi

afl-fuzz -m none -i ./in -o ./out -- $target @@
