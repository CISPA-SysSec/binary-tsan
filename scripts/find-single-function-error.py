import sys
import os
import subprocess
import random

if len(sys.argv) != 2:
    print("Usage: python3 " + sys.argv[0] + " build-folder")
    exit(1)

os.chdir(sys.argv[1])

# TODO: make these command line arguments
inFile = "ls"
outFile = "ls-mod"
runFile = ["./ls-mod", "--time=birth", "-l", "a"]
checkOnlyFunctions = []
timeoutIsFailure = True
iterations = 30
manualCheck = False
enableSanityChecks = True


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
        #environmentVariables["LD_LIBRARY_PATH"] = "/home/andi/Masterarbeit/binary-tsan/build/instrumented-libraries"
        #environmentVariables["TSAN_OPTIONS"] = "report_signal_unsafe=0"
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

def checkFunctions(functionNames, extraArguments):
    nameFile = open(functionFileName, "w")
    for name in functionNames:
        nameFile.write(name)
    nameFile.close()
    res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--instrument-only-functions=" + functionFileName, "--clean"] + extraArguments,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print("Instrumenting failed!")
        exit(1)
    return checkError()

# TODO: clear environment variables

# TODO: print error if it fails
functionFileName = os.path.join(os.path.realpath(sys.argv[1]), "functionnames")

if len(checkOnlyFunctions) > 0:
    functionNames = checkOnlyFunctions
    hasProblem = True
else:
    print("Getting function names")
    res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--dump-function-names-to=" + functionFileName, "--clean"],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if not checkError():
        print("Full instrumentation does not fail!")
        exit(1)

    functionNames = []
    for line in open(functionFileName, "r").readlines():
        functionNames.append(line)

while len(functionNames) > 1:
    p1 = functionNames[:len(functionNames)//2]
    p2 = functionNames[len(functionNames)//2:]
    
    print("Testing " + str(len(p1)) + " functions")
    hasProblem = checkFunctions(p1, [])
    
    if hasProblem:
        print("The problem is in this subset")
        functionNames = p1
        if len(p1) < 10:
            print(p1)
    else:
        print("There is no problem in this subset")
        
        if enableSanityChecks:
            print("Sanity checking other subset")
            if not checkFunctions(p2, []):
                print("ERROR: sanity check failed, shuffling")
                random.shuffle(functionNames)
            else:
                functionNames = p2
        else:
            functionNames = p2

print("Problem function: " + functionNames[0])
print("Generate with: ./thread-sanitizer.sh " + inFile + " " + outFile + " --instrument-only-functions=" + functionFileName)
print("")

if not hasProblem:
    print("Checking that the function really causes a problem")
    if not checkFunctions(functionNames, []):
        print("ERROR: the function does not cause a problem")
        exit(1)

print("Checking function entry/exit and getting instruction addresses")
instructionFileName = os.path.join(os.path.realpath(sys.argv[1]), "instructionAddresses")
if not checkFunctions(functionNames, ["--no-entry-exit", "--dump-instrumented-instructions=" + instructionFileName]):
    print("The problem is the entry/exit instrumentation")
    exit(0)

virtualOffsets = []
for line in open(instructionFileName, "r").readlines():
    virtualOffsets.append(line.replace("\n", ""))
allOffsets = virtualOffsets.copy()
    
annotationFilename = os.path.join(os.path.realpath(sys.argv[1]), "annotations")

def checkInstructions(instrumentInstructions, allInstructions):
    nameFile = open(annotationFilename, "w")
    for name in allInstructions:
        if not name in instrumentInstructions:
            nameFile.write(name + " ignore\n")
    nameFile.close()
    
    res = subprocess.run(["./thread-sanitizer.sh", inFile, outFile, "--instrument-only-functions=" + functionFileName, "--no-entry-exit",
                          "--annotations=" + annotationFilename, "--clean"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if res.returncode != 0:
        print("Instrumenting failed!")
        exit(1)
    return checkError()

print("Checking subsets of instructions!")
while len(virtualOffsets) > 1:
    p1 = virtualOffsets[:len(virtualOffsets)//2]
    p2 = virtualOffsets[len(virtualOffsets)//2:]
    
    print("Testing " + str(len(p1)) + " instructions")
    hasProblem = checkInstructions(p1, allOffsets)
    
    if hasProblem:
        print("The problem is in this subset")
        virtualOffsets = p1
        if len(p1) < 10:
            print(p1)
    else:
        print("There is no problem in this subset")
        
        if enableSanityChecks:
            print("Sanity checking other subset")
            if not checkInstructions(p2, allOffsets):
                print("ERROR: sanity check failed, shuffling")
                random.shuffle(virtualOffsets)
            else:
                virtualOffsets = p2
        else:
            virtualOffsets = p2

print("Problem instruction: " + virtualOffsets[0])

print("Generate with: ./thread-sanitizer.sh " + inFile + " " + outFile + " --instrument-only-functions=" + functionFileName + " --no-entry-exit --annotations=" + annotationFilename)
