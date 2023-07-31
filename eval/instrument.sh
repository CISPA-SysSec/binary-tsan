#!/bin/bash

last=$PWD
targetpath=$1
target=$(basename $targetpath)

echo "SETUP ENVIRONMENT"
cd /home/joschua/Desktop/CISPA/Projekte/zipr/
. set_env_vars
cd /home/joschua/Desktop/CISPA/Projekte/zafl/
. set_env_vars
cd $last
echo "environment variables set"

if test "$2" = "-c"; then
    rm -rf ./tsan_temp.*
    rm -rf ./peasoup_executable_directory.*
    echo "old files cleaned"
fi

echo ""
echo ""
echo "--------------------------------"

echo "BUILD SANITIZED"
../build/thread-sanitizer.sh $PWD/$targetpath $PWD/instrumented/$target.san 
#--use-system-libtsan #--register-analysis=none
#../build/thread-sanitizer.sh $PWD/$targetpath $PWD/instrumented/$target.noatom --no-instrument-atomics 


echo "BUILD NODRA"
../build/thread-sanitizer.sh $PWD/$targetpath $PWD/instrumented/$target.nodra --register-analysis=none 

echo "BUILD STAR"
../build/thread-sanitizer.sh $PWD/$targetpath $PWD/instrumented/$target.star --register-analysis=stars
#--use-system-libtsan
#--no-add-tsan-calls
#--no-instrument-stack 
#--use-memory-profiler
#--dry-run
#--register-analysis=(none|stars|custom)
echo ""
echo ""
echo "--------------------------------"

echo "BUILD ZAFL"
#./zafl.sh $PWD/$targetpath $PWD/instrumented/$target.zaf
echo ""
echo ""
echo "--------------------------------"



echo "BUILD SAN-ZAFL"
#./zafl.sh $PWD/$targetpath $PWD/instrumented/$target.sanzaf -T
echo ""
echo ""
echo "--------------------------------"
