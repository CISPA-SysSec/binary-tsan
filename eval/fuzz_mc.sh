export AFL_SKIP_BIN_CHECK=1
export TSAN_OPTIONS=abort_on_error=1:symbolize=0

runLength=$((60*60*24)) #in seconds

target=""

if [ $# -eq 0 ]
then
    target="./test.sanzaf"
else
    target=$1
fi

echo "Fuzzing target: $target \n"

echo "Fuzzing Command:"
echo "afl-fuzz -m none -t 10000 -V $runLength -i ./in -o ./sync -M fuzzer01 -- $target $2 $3 $4 $5"

tmux new-session -d -s "fuzzer01" "afl-fuzz -m none -t 10000 -V $runLength -i ./in -o ./sync -M fuzzer01 -- $target $2 $3 $4 $5"

maxThreads="$(grep -c ^processor /proc/cpuinfo)"

echo "Start Fuzzer with $maxThreads instances"

for ((i=2;i<=$maxThreads; i++))
do
    if ((i<10));
    then
    number="0$i"
    else
    number="$i"
    fi
    tmux new-session -d -s "fuzzer$number" afl-fuzz -m none -t 10000 -V $runLength -i ./in -o ./sync -S fuzzer$number -- $target $2 $3 $4 $5
done


