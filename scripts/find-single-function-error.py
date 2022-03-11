import sys
import os
import subprocess

if len(sys.argv) != 2:
    print("Usage: python3 " + sys.argv[0] + " build-folder")
    exit(1)

os.chdir(sys.argv[1])

# TODO: make these command line arguments
inFile = "libaws-orig.so"
outFile = "instrumented-libraries/libaws.so.5"
runFile = ["./wps-mod"]
timeoutIsFailure = False
iterations = 1
manualCheck = True


def checkError():
    if manualCheck:
        # alert the user, will only work when package "sox" is installed
        os.system("play -q -n synth 1 sin 880")
        while True:
            correctString = input("Please check for errors manually, report Error/Fine: ")
            if correctString == "Error":
                return True
            if correctString == "Fine":
                return False
            print("Could not parse answer")
        
    else:
        environmentVariables = dict(os.environ)
        environmentVariables["LD_LIBRARY_PATH"] = "/home/andi/Masterarbeit/binary-tsan/build/instrumented-libraries"
        environmentVariables["TSAN_OPTIONS"] = "report_signal_unsafe=0"
        for i in range(iterations):
            try: 
                res = subprocess.run(runFile, env=environmentVariables, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=50)
                hasProblem = res.returncode != 0
                outStr = str(res.stdout)
                if "ThreadSanitizer: SEGV" in outStr or "Aborted" in outStr or "FATAL: ThreadSanitizer CHECK failed:" in outStr or "raised " in outStr:
                    return True
            except:
                print("Execution timeout")
                if timeoutIsFailure:
                    return True
    return False

def checkFunctions(functionNames):
    nameFile = open(functionFileName, "w")
    for name in functionNames:
        nameFile.write(name)
    nameFile.close()
    res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--instrumentOnlyFunctions=" + functionFileName],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print("Instrumenting failed!")
        exit(1)
    return checkError()

# TODO: clear environment variables

# TODO: print error if it fails
print("Getting function names")
functionFileName = os.path.join(os.path.realpath(sys.argv[1]), "functionnames")
res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--dumpFunctionNamesTo=" + functionFileName, "--dry-run"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

if checkError():
    print("Dry run instrumentation fails!")
    exit(1)

functionNames = []
for line in open(functionFileName, "r").readlines():
    functionNames.append(line)

while len(functionNames) > 1:
    p1 = functionNames[:len(functionNames)//2]
    p2 = functionNames[len(functionNames)//2:]
    
    print("Testing " + str(len(p1)) + " functions")
    hasProblem = checkFunctions(p1)
    
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

if not hasProblem:
    print("Checking that the function really causes a problem")
    if not checkFunctions(functionNames):
        print("ERROR: the function does not cause a problem")
        exit(1)

