import sys
import os
import subprocess
import signal

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " tsan-script parsec-directory")
    exit(1)

# if set to false, previously instrumented binaries are used
instrumentBinaries = False
benchmarkHelgrind = True
runTarget = "simsmall"
timeout = 220
iterations = 5
baseCommand = ["./bin/parsecmgmt", "-a", "run", "-i", runTarget, "-n", "2"]

# x264, vips, raytrace, bodytrack, facesim, ferret are destroyed by zipr (even when no thread sanitizer code runs)
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
        for i in range(iterations):
            try:
                environmentVariables = dict(os.environ)
                #environmentVariables["TSAN_OPTIONS"] = "report_bugs=0"
                p = subprocess.Popen(runCommand + ["-p", testcase], start_new_session=True, env=environmentVariables, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                outs, errs = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                result[testcase] = "timeout"
                totalTime = 0
                break
            outStr = str(outs)
            for line in outStr.split("\\n"):
                if "Segmentation fault" in line or "ThreadSanitizer: SEGV" in line:
                    result[testcase] = "segfault"
                    totalTime = 0
                    break
                if line.startswith("real\\t"):
                    time = line.replace("real\\t", "")
                    totalTime = totalTime + timeStrToNumber(time)
            if totalTime == 0:
                break
        if totalTime > 0:
            result[testcase] = str(totalTime / iterations)
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
        instDir = os.path.join(sys.argv[2], "pkgs/apps/" + name + "/inst/")
        binaryIn = instDir + "amd64-linux.gcc/bin/" + execName # TODO: pre removed
        outDir = instDir + "amd64-linux.gcc.btsan"
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
    print("    * base: ".ljust(20) + baseTimes[name])
    print("    * tsan: ".ljust(20) + tsanTimes[name])
    print("    * btsan: ".ljust(20) + btsanTimes[name])
    if benchmarkHelgrind:
        print("    * helgrind: ".ljust(20) + valgrindTimes[name])

print("")

dataString = "["
for name in tests:
    if timeStrToNumber(baseTimes[name]) == 0:
        continue
    dataString = dataString + "(\"" + name + "\", [" + str(timeStrToNumber(baseTimes[name]))
    dataString = dataString + ", " + str(timeStrToNumber(tsanTimes[name]))
    dataString = dataString + ", " + str(timeStrToNumber(btsanTimes[name]))
    if benchmarkHelgrind:
        dataString = dataString + ", " + str(timeStrToNumber(valgrindTimes[name]))
    dataString = dataString + "]), "
dataString = dataString + "]"
print(dataString)

