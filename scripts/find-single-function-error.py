import sys
import os
import subprocess

if len(sys.argv) != 2:
    print("Usage: python3 " + sys.argv[0] + " build-folder")
    exit(1)

os.chdir(sys.argv[1])

# TODO: make these command line arguments
inFile = "freqmine"
outFile = "freqmine-mod"
runFile = ["./freqmine-mod", "kosarak_250k.dat", "220"]
timeoutIsFailure = True

# TODO: clear environment variables

# TODO: print error if it fails
print("Getting function names")
functionFileName = os.path.join(os.path.realpath(sys.argv[1]), "functionnames")
res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--dumpFunctionNamesTo=" + functionFileName, "--dry-run"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

functionNames = []
for line in open(functionFileName, "r").readlines():
    functionNames.append(line)

while len(functionNames) > 1:
    p1 = functionNames[:len(functionNames)//2]
    p2 = functionNames[len(functionNames)//2:]
    nameFile = open(functionFileName, "w")
    for name in p1:
        nameFile.write(name)
    nameFile.close()
    # TODO: print number of interations
    print("Testing " + str(len(p1)) + " functions")
    res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--instrumentOnlyFunctions=" + functionFileName],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print("Instrumenting failed!")
        exit(1)
    environmentVariables = dict(os.environ)
    environmentVariables["LD_LIBRARY_PATH"] = "/home/andi/Masterarbeit/binary-tsan/build/instrumented-libraries"
    environmentVariables["TSAN_OPTIONS"] = "exitcode=0"
    hasProblem = False
    for i in range(50):
        try: 
            res = subprocess.run(runFile, env=environmentVariables, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=50)
            hasProblem = res.returncode != 0
            outStr = str(res.stdout)
            if "ThreadSanitizer: SEGV" in outStr or "Aborted" in outStr or "FATAL: ThreadSanitizer CHECK failed:" in outStr:
                hasProblem = True
                break
        except:
            print("Execution timeout")
            if timeoutIsFailure:
                hasProblem = True
                break
    
    if hasProblem:
        print("The problem is in this subset")
        functionNames = p1
        if len(p1) < 10:
            print(p1)
    else:
        print("There is no problem in this subset")
        functionNames = p2

print("Problem function: " + functionNames[0])
print("Generate with: ./thread-sanitizer.sh " + inFile + " " + outFile + " --instrumentOnlyFunctions=" + functionFileName)

# TODO: delete function name file
