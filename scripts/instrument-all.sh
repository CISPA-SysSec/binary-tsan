if [ "$#" -ne 2 ]
then
	echo ""
	echo "Usage: $0 <thread-sanitizer-script> <search-folder>"
	exit 1
fi

for i in `find $2 -type f -executable`;
do
    if file $i | grep -i "ELF 64-bit LSB shared object" >/dev/null;
    then
        echo "Instrumenting $i"
        filename=$(basename $i)
        $1 $i $filename --clean
        if [ $? -ne 0 ]
        then
            exit 1
        fi
    fi
done
