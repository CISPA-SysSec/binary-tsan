export AFL_SKIP_BIN_CHECK=1
export TSAN_OPTIONS=abort_on_error=1:symbolize=0

target=""

if [ $# -eq 0 ]
then
    target="./test.sanzaf"
else
    target=$1
fi

echo "Fuzzing target: $target \n"

echo "afl-fuzz -m none -t 10000 -i ./in -o ./out -- $target $2 $3 $4 $5"

afl-fuzz -m none -t 10000 -i ./in -o ./out -- $target $2 $3 $4 $5
