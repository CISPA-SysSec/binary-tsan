import sys
import os
import subprocess
import psutil
import time

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " tsan-script parsec-directory")
    exit(1)



tests = ["blackscholes", "bodytrack", "ferret", "freqmine"]#["blackscholes", "bodytrack", "facesim", "ferret", "fluidanimate", "freqmine", "raytrace", "swaptions", "vips"]
# the test name is used if not present here
executableNames = {
    "raytrace": "rtview"
}

def runGetMemory(command):
    process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    maxVmsMemory = 0
    maxRssMemory = 0
    while True:
        returncode = process.poll()
        if returncode != None:
            break
        
        try:
            pp = psutil.Process(process.pid)

            descendants = list(pp.children(recursive=True))
            descendants = descendants + [pp]

            rssMemory = 0
            vmsMemory = 0
            for descendant in descendants:
                try:
                    memInfo = descendant.memory_info()
                    rssMemory += memInfo.rss
                    vmsMemory += memInfo.vms
                except psutil.NoSuchProcess:
                    pass
            
            maxRssMemory = max(maxRssMemory, rssMemory)
            maxVmsMemory = max(maxVmsMemory, vmsMemory)

        except psutil.NoSuchProcess:
            break
        
        time.sleep(0.5)
    return (returncode, maxRssMemory)


def getInstrumentTime(options):
    result = {}
    for name in tests:
        execName = name
        if name in executableNames:
            execName = executableNames[name]
        instDir = os.path.join(sys.argv[2], "pkgs/apps/" + name + "/inst/")
        binaryIn = instDir + "amd64-linux.gcc/bin/" + execName
        outDir = instDir + "amd64-linux.gcc.btsan"
        hasOutDir = os.path.isdir(outDir)
        if not hasOutDir:
            os.mkdir(outDir)
            os.mkdir(outDir + "/bin")
        binaryOut = outDir + "/bin/" + execName
        
        startTime = time.time()
        (returncode, memory) = runGetMemory([sys.argv[1], binaryIn, binaryOut] + options)
        if returncode != 0:
            print("Instrumenting " + name + " failed!")
            exit(1)
        executionTime = (time.time() - startTime)
        result[name] = (executionTime, memory)
    return result


def getCompileTime(typeSelect):
    startDir = os.getcwd()
    os.chdir(sys.argv[2])
    
    print("Compiling tools")
    tools = []
    if "raytrace" in tests:
        tools.append("cmake")
    if "x264" in tests:
        tools.append("yasm")
    if len(tools) > 0:
        clearCommand = ["./bin/parsecmgmt", "-a", "uninstall", "-p"] + typeSelect + typeSelect
        res = subprocess.run(clearCommand, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        compileCommand = ["./bin/parsecmgmt", "-a", "build", "-p"] + tools + typeSelect
        subprocess.run(compileCommand, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    
    result = {}
    for testcase in tests:
        # the compilation time for the libraries has to be in the time for every program separately
        libraries = ["glib", "gsl", "hooks", "libjpeg", "libxml2", "meas", "parmacs", "ssl", "tbblib", "uptcpip", "zlib"]
        clearCommand = ["./bin/parsecmgmt", "-a", "uninstall", "-p", testcase] + libraries + typeSelect
        res = subprocess.run(clearCommand, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        runCommand = ["./bin/parsecmgmt", "-a", "build", "-p", testcase] + typeSelect
        
        startTime = time.time()
        (returncode, memory) = runGetMemory(runCommand + ["-p", testcase])
        executionTime = (time.time() - startTime)
        
        result[testcase] = (executionTime, memory)
    os.chdir(startDir)
    return result

print("Compiling base executables")
baseTimes = getCompileTime([])

print("Compiling regular thread sanitizer")
tsanTimes = getCompileTime(["-c", "gcc-tsan"])

print("Instrumenting with wrappers")
btsanMinimalTimes = getInstrumentTime(["--use-wrapper-functions"])

print("Instrumenting with stars register analysis")
btsanStarsRegisterAnalysis = getInstrumentTime(["--register-analysis=stars"])

# must stay last to always have normal instrumented binaries in the parsec folder for benchmarks
print("Instrumenting with default options")
btsanTimes = getInstrumentTime([])


for name in tests:
    print(name + ": ")
    print("    * base: ".ljust(20) + "{0:.2f}".format(baseTimes[name][0]))
    print("    * tsan: ".ljust(20) + "{0:.2f}".format(tsanTimes[name][0]))
    print("    * btsan: ".ljust(20) + "{0:.2f}".format(btsanTimes[name][0]))
    print("    * btsan minimal: ".ljust(20) + "{0:.2f}".format(btsanMinimalTimes[name][0]))
    print("    * btsan stars: ".ljust(20) + "{0:.2f}".format(btsanStarsRegisterAnalysis[name][0]))

print("")

def formatMemory(byte):
    if byte < 1024:
        return str(byte) + " b"
    byte = byte // 1024
    if byte < 1024:
        return str(byte) + " kb"
    byte = byte // 1024
    if byte < 1024:
        return str(byte) + " mb"
    return str(byte // 1024) + " gb " + str(byte % 1024) + " mb"

print("Memory requirements:")
for name in tests:
    print(name + ": ")
    print("    * base: ".ljust(20) + formatMemory(baseTimes[name][1]))
    print("    * tsan: ".ljust(20) + formatMemory(tsanTimes[name][1]))
    print("    * btsan: ".ljust(20) + formatMemory(btsanTimes[name][1]))
    print("    * btsan minimal: ".ljust(20) + formatMemory(btsanMinimalTimes[name][1]))
    print("    * btsan stars: ".ljust(20) + formatMemory(btsanStarsRegisterAnalysis[name][1]))

dataString = "["
for name in tests:
    dataString = dataString + "(\"" + name + "\", [" + str(baseTimes[name])
    dataString = dataString + ", " + str(tsanTimes[name])
    dataString = dataString + ", " + str(btsanTimes[name])
    dataString = dataString + ", " + str(btsanMinimalTimes[name])
    dataString = dataString + ", " + str(btsanStarsRegisterAnalysis[name])
    dataString = dataString + "]), "
dataString = dataString + "]"
print(dataString)

