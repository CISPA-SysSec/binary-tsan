#! /usr/bin/python3

import sys
import os
import subprocess
import signal
import re

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " tsan-script parsec-directory")
    exit(1)

# if set to false, previously instrumented binaries are used
instrumentBinaries = True

benchmarkDefault = False
benchmarkBinTSAN = True
benchmarkCompTSAN = False
benchmarkHelgrind = False



benchmarkWithoutDRA = False
benchmarkWithSTARS = False

runTarget = "simsmall"
timeout = 60*60
iterations = 5
# raytrace will always be executed with one thread since it deadlocks otherwise
threads = 4
baseCommand = [sys.argv[2]+"/bin/parsecmgmt", "-a", "run", "-i", runTarget]
#output folder
OUTPUT_FOLDER = "/home/XXXXXXXXXXX/PARSEC_outputs/"

# Warning: ferret requires libjpeg.so.62, package libjpeg62-dev must be installed
# ["dedup", "ferret", "blackscholes", "streamcluster", "fluidanimate", "swaptions", "vips", "bodytrack", "raytrace"]
# ["canneal", "facesim", "x264"] # not working
# ["freqmine"] # excluded because does not use pthreads
tests = ["fluidanimate", "ferret", "vips", "streamcluster", "bodytrack"]#, "fluidanimate", "streamcluster"]#["dedup", "ferret", "blackscholes", "streamcluster", "fluidanimate", "swaptions", "vips", "bodytrack", "raytrace"]
# the test name is used if not present here
executableNames = {
    "raytrace": "rtview"
}

def timeStrToNumber(timeStr):
    parts = timeStr.split("m")
    if len(parts) != 2 or timeStr == "timeout":
        return 0
    return int(parts[0]) * 60 + float(parts[1][:-1].replace(",", "."))

def getTimes(runCommand, benchType):
    startDir = os.getcwd()
    os.chdir(sys.argv[2])
    
    result = {}
    for testcase in tests:
        #print(testcase)
        result[testcase] = "not found"
        totalTime = 0
        minWarnings = 1000000
        maxWarnings = 0
        for i in range(iterations):
            try:
                environmentVariables = dict(os.environ)
                #environmentVariables["TSAN_OPTIONS"] = "report_bugs=0"
                numThreads = threads
                if testcase == "raytrace":
                    numThreads = 1
                fullCommand = runCommand + ["-p", testcase, "-n", str(numThreads)]
                print(fullCommand)
                p = subprocess.Popen(fullCommand, start_new_session=True, env=environmentVariables, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                outs, errs = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                result[testcase] = "timeout"
                totalTime = 0
                break
            outStr = str(outs)

            #if("helgrind" in " ".join(runCommand)):
                #print("log written")
            with open(OUTPUT_FOLDER+"/"+testcase+"."+benchType+str((i+1)), "wb") as binary_file:
                binary_file.write(outs)

            #print(outStr)
            errorCount = 0
            for line in outStr.split("\\n"):
                if "Segmentation fault" in line or "ThreadSanitizer: SEGV" in line:
                    result[testcase] = "segfault"
                    totalTime = 0
                    break
                if line.startswith("real\\t"):
                    time = line.replace("real\\t", "")
                    totalTime = totalTime + timeStrToNumber(time)
                
                count = re.findall('ThreadSanitizer: reported ([0-9]+) warnings', line)
                if len(count) > 0:
                    errorCount = int(count[0])
                count = re.findall('== ERROR SUMMARY: ([0-9]+) errors', line)
                if len(count) > 0:
                    errorCount = int(count[0])
            
            minWarnings = min(minWarnings, errorCount)
            maxWarnings = max(maxWarnings, errorCount)
                    
                    
            if totalTime == 0:
                break
        if totalTime > 0:
            result[testcase] = (totalTime / iterations, minWarnings, maxWarnings)
    os.chdir(startDir)
    return result


def instrBin(instrCommand):
    print("Instrumenting binaries")
    for name in tests:
        execName = name
        if name in executableNames:
            execName = executableNames[name]
        subfolder = "apps"
        if name == "dedup" or name == "canneal" or name == "streamcluster":
            subfolder = "kernels"
        instDir = os.path.join(sys.argv[2], "pkgs", subfolder, name, "inst")
        binaryIn = os.path.join(instDir, "amd64-linux.gcc", "bin", execName) # TODO: pre removed
        outDir = os.path.join(instDir, "amd64-linux.gcc.btsan")

        if(instrCommand == "--register-analysis=none"):
            outDir = os.path.join(instDir, "amd64-linux.gcc.btsan-noDRA")
        elif(instrCommand == "--register-analysis=stars"):
            outDir = os.path.join(instDir, "amd64-linux.gcc.btsan-starDRA")

        hasOutDir = os.path.isdir(outDir)
        if not hasOutDir:
            os.mkdir(outDir)
            os.mkdir(outDir + "/bin")
        binaryOut = outDir + "/bin/" + execName
        
        if(instrCommand == ""):
            print(" ".join(([sys.argv[1], binaryIn, binaryOut])))
            res = subprocess.run([sys.argv[1], binaryIn, binaryOut], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        else:
            print(" ".join(([sys.argv[1], binaryIn, binaryOut, instrCommand])))
            res = subprocess.run([sys.argv[1], binaryIn, binaryOut, instrCommand], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if res.returncode != 0:
            print("Instrumenting " + name + " failed!")
            exit(1)
    return



if(benchmarkDefault):
    print("Running base executables")
    baseTimes = getTimes(baseCommand, "default")

if(benchmarkCompTSAN):
    print("Running regular thread sanitizer")
    tsanTimes = getTimes(baseCommand + ["-c", "gcc-tsan"], "tsan")


if benchmarkHelgrind:
    print("Running with helgrind")
    valgrindTimes = getTimes(baseCommand + ["-s", "time valgrind --tool=helgrind "], "hel")


if instrumentBinaries:
    if(benchmarkBinTSAN):
        instrBin("")
    if(benchmarkWithoutDRA):
        instrBin("--register-analysis=none")
    if(benchmarkWithSTARS):
        instrBin("--register-analysis=stars")


if(benchmarkBinTSAN):
    print("Running binary thread sanitized binaries")
    btsanTimes = getTimes(baseCommand + ["-x", "btsan"], "san")


if(benchmarkWithoutDRA):
    print("Running binary thread sanitized binaries")
    btsanNoDRATimes = getTimes(baseCommand + ["-x", "btsan-noDRA"], "nodra")

if(benchmarkWithSTARS):
    print("Running binary thread sanitized binaries")
    btsanStarDRATimes = getTimes(baseCommand + ["-x", "btsan-starDRA"], "start")




for name in tests:
    print(name + ": ")
    if(benchmarkDefault): 
        print("    * base: ".ljust(20) + str(baseTimes[name][0]))
    if(benchmarkCompTSAN): 
        print("    * tsan: ".ljust(20) + str(tsanTimes[name][0]))
    if(benchmarkBinTSAN): 
        print("    * btsan: ".ljust(20) + str(btsanTimes[name][0]))
    if(benchmarkWithoutDRA): 
        print("    * btsan without DRA: ".ljust(20) + str(btsanNoDRATimes[name][0]))
    if(benchmarkWithSTARS): 
        print("    * btsan with STARS DRA: ".ljust(20) + str(btsanStarDRATimes[name][0]))
    if benchmarkHelgrind:
        print("    * helgrind: ".ljust(20) + str(valgrindTimes[name][0]))

print("")

dataString = "["
for name in tests:
    if(benchmarkDefault):
        if baseTimes[name][0] == 0:
            continue
        dataString = dataString + "(\"" + name + "\", [" + str(baseTimes[name])
    if(benchmarkCompTSAN):
        dataString = dataString + ", " + str(tsanTimes[name])
    if(benchmarkBinTSAN):
        dataString = dataString + ", " + str(btsanTimes[name])
    if(benchmarkWithoutDRA):
        dataString = dataString + ", " + str(btsanNoDRATimes[name])
    if(benchmarkWithSTARS):
        dataString = dataString + ", " + str(btsanStarDRATimes[name])
    if benchmarkHelgrind:
        dataString = dataString + ", " + str(valgrindTimes[name])
    dataString = dataString + "]), "
dataString = dataString + "]"

print(dataString)

