#!/bin/bash

last=$PWD
cd /home/joschua/Desktop/CISPA/Projekte/zipr/
. set_env_vars
cd /home/joschua/Desktop/CISPA/Projekte/zafl/
. set_env_vars
cd $last


$( dirname -- "$0"; )/../../zafl/bin/zafl.sh -r 42 $3 $4 $5 $6 $7 $8 $9 -M $1 $2
