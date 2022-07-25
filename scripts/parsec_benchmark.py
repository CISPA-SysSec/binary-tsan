import sys
import os
import subprocess
import signal
import re

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " tsan-script parsec-directory")
    exit(1)

# if set to false, previously instrumented binaries are used
instrumentBinaries = False
benchmarkHelgrind = True
runTarget = "simsmall"
timeout = 300
iterations = 1
# raytrace will always be executed with one thread since it deadlocks otherwise
threads = 2
baseCommand = ["./bin/parsecmgmt", "-a", "run", "-i", runTarget]

# Warning: ferret requires libjpeg.so.62, package libjpeg62-dev must be installed
tests = ["blackscholes", "ferret", "fluidanimate", "freqmine", "swaptions"]#["blackscholes", "ferret", "fluidanimate", "freqmine", "swaptions"]["ferret"]#
# the test name is used if not present here
executableNames = {
    "raytrace": "rtview"
}

def timeStrToNumber(timeStr):
    parts = timeStr.split("m")
    if len(parts) != 2 or timeStr == "timeout":
        return 0
    return int(parts[0]) * 60 + float(parts[1][:-1])

def getTimes(runCommand):
    startDir = os.getcwd()
    os.chdir(sys.argv[2])
    
    result = {}
    for testcase in tests:
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
                p = subprocess.Popen(runCommand + ["-p", testcase, "-n", str(numThreads)], start_new_session=True, env=environmentVariables, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                outs, errs = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                result[testcase] = "timeout"
                totalTime = 0
                break
            outStr = str(outs)
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

print("Running base executables")
baseTimes = getTimes(baseCommand)

print("Running regular thread sanitizer")
tsanTimes = getTimes(baseCommand + ["-c", "gcc-tsan"])


if benchmarkHelgrind:
    print("Running with helgrind")
    valgrindTimes = getTimes(baseCommand + ["-s", "time valgrind --tool=helgrind "])

if instrumentBinaries:
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
        hasOutDir = os.path.isdir(outDir)
        if not hasOutDir:
            os.mkdir(outDir)
            os.mkdir(outDir + "/bin")
        binaryOut = outDir + "/bin/" + execName
        
        res = subprocess.run([sys.argv[1], binaryIn, binaryOut], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if res.returncode != 0:
            print("Instrumenting " + name + " failed!")
            exit(1)

print("Running binary thread sanitized binaries")
btsanTimes = getTimes(baseCommand + ["-x", "btsan"])

for name in tests:
    print(name + ": ")
    print("    * base: ".ljust(20) + str(baseTimes[name][0]))
    print("    * tsan: ".ljust(20) + str(tsanTimes[name][0]))
    print("    * btsan: ".ljust(20) + str(btsanTimes[name][0]))
    if benchmarkHelgrind:
        print("    * helgrind: ".ljust(20) + str(valgrindTimes[name][0]))

print("")

dataString = "["
for name in tests:
    if baseTimes[name][0] == 0:
        continue
    dataString = dataString + "(\"" + name + "\", [" + str(baseTimes[name])
    dataString = dataString + ", " + str(tsanTimes[name])
    dataString = dataString + ", " + str(btsanTimes[name])
    if benchmarkHelgrind:
        dataString = dataString + ", " + str(valgrindTimes[name])
    dataString = dataString + "]), "
dataString = dataString + "]"
print(dataString)

