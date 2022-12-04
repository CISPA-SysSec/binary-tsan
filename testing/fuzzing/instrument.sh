#!/bin/bash

last=$PWD
target=$1

echo "SETUP ENVIRONMENT"
cd /home/joschua/Desktop/CISPA/Projekte/zipr/
. set_env_vars
cd /home/joschua/Desktop/CISPA/Projekte/zafl/
. set_env_vars
cd $last
echo "environment variables set"

rm -rf ./tsan_temp.*
rm -rf ./peasoup_executable_directory.*
echo "old files cleaned"
echo ""
echo ""
echo "--------------------------------"

#echo "BUILD SANITIZED"
#../../build/thread-sanitizer.sh $PWD/targets/$target $PWD/targets_instrumented/$target.san
#
#echo ""
#echo ""
#echo "--------------------------------"
#
echo "BUILD ZAFL"
../zafl.sh $PWD/targets/$target $PWD/targets_instrumented/$target.zaf
echo ""
echo ""
echo "--------------------------------"

echo "BUILD SAN-ZAFL"
../zafl.sh $PWD/targets/$target $PWD/targets_instrumented/$target.sanzaf -T
echo ""
echo ""
echo "--------------------------------"
