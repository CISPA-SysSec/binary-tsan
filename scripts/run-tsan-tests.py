import os
import subprocess
import sys
import re
import threading
import filecheck
import signal

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " thread-sanitizer-script output-folder")
    quit()

# TODO: do not hardcode
clang = "clang"
testDirectory = os.path.realpath("../tests/")
testSubDirectories = ["bugs", "repstring", "atomics", "llvm-tsan-tests"]

numThread = 3
outputdir = os.path.realpath(sys.argv[2])
runScript = os.path.realpath(sys.argv[1])

scriptPath = os.path.dirname(os.path.abspath(__file__))
toolPath = os.path.abspath(os.path.join(scriptPath, "../tools"))
os.chdir(outputdir)

exclude = []
runOnly = []

invalid = []

total = 0
failed = 0
setupFailed = 0
compilerTSanFailed = 0

def performBasicReplacements(line):
    p1 = line.replace("// RUN: ", "").replace("\n", "")
    p1 = p1.replace("%env_tsan_opts", "env TSAN_OPTIONS")
    p1 = p1.replace("FileCheck", toolPath + "/FileCheck")
    if p1.startswith("not "):
        p1 = " " + p1
    p1 = p1.replace(" not ", " " + toolPath + "/not ")
    p1 = p1.replace("%deflake", scriptPath + "/deflake.bash 10")
    p1 = p1.replace("%link_libcxx_tsan", "-ldl")
    p1 = p1.replace("%darwin_min_target_with_tls_support", "")
    p1 = p1.replace("%os", "Linux")
    p1 = p1.replace("%run", "")
    return p1

def testCommand(command, timeout):
    try:
        p = subprocess.Popen(command, start_new_session=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        outs, errs = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        return False
    return p.returncode == 0

def checkFile(testFile):
    global total
    global failed
    global setupFailed
    global compilerTSanFailed
    
    filename = os.path.basename(testFile)
    
    f = os.path.join(testDirectory, testFile)
    outfile = os.path.join(outputdir, filename.replace(".cpp", "").replace(".c", ""))

    runLines = []
    for line in open(f, "r").readlines():
        if "// RUN: " in line:
            runLines.append(line)
    
    for line in runLines:
        p1 = performBasicReplacements(line)
        c2 = p1.replace("%t", outfile + "-thread")
        c2 = c2.replace("%clang_tsan", clang + " -fsanitize=thread")
        c2 = c2.replace("%gcc_tsan", "gcc -fsanitize=thread -lpthread")
        c2 = c2.replace("%g++_tsan", "g++ -fsanitize=thread -lpthread")
        c2 = c2.replace("%clangxx_tsan", clang + " -fsanitize=thread -lstdc++")
        c2 = c2.replace("%s", f)
        
        if not testCommand(c2, 60):
            print("Test: " + testFile)
            print("\tFailed to run ordinary tests")
            compilerTSanFailed = compilerTSanFailed + 1
            return
        
    for line in runLines:
        p1 = performBasicReplacements(line)
        c1 = p1.replace("%clang_tsan", clang + " -lpthread -ltsan")
        c1 = c1.replace("%gcc_tsan", "gcc -lpthread")
        c1 = c1.replace("%g++_tsan", "g++ -lpthread")
        c1 = c1.replace("%clangxx_tsan", clang + " -lpthread -ltsan -lstdc++")
        c1 = c1.replace("%s", f)
        if not "%clang" in p1 and not "%gcc" in p1 and not "%g++" in p1:
            instrumentedBinary = outfile + "-mod"
            c1 = c1.replace("%t", instrumentedBinary)
            os.system(c1)
            continue
        
        compileCommand = c1.split("&&")[0]
        fullOutFile = "%t"
        if "%t" in compileCommand:
            matches = re.findall("-o (%t[^\s]+) ?", compileCommand)
            if len(matches) > 0:
                fullOutFile = matches[0].strip()
        
        compileCommand = compileCommand.replace("%t", outfile)
        res = subprocess.run(compileCommand.split(" "), capture_output=True)
        if res.returncode != 0:
            setupFailed = setupFailed + 1
            print("Test: " + testFile)
            print("\tFailed to compile " + testFile)
            return
        
        total = total + 1
        
        inputBinary = fullOutFile.replace("%t", outfile)
        instrumentedBinary = fullOutFile.replace("%t", outfile + "-mod")
        instrumentParts = [runScript, inputBinary, instrumentedBinary]
        if "-fno-sanitize-thread-atomics" in compileCommand or "-tsan-instrument-atomics=0" in compileCommand:
            instrumentParts.append("--no-instrument-atomics")
        res = subprocess.run(instrumentParts, capture_output=True)
        if res.returncode != 0:
            print("Test: " + testFile)
            print("\tInstrumenting the binary failed:")
            print(str(res.stdout).replace("\\n", "\n"))
            invalid.append(testFile)
            failed = failed + 1
            return
        
        runCommand = c1.replace(c1.split("&&")[0] + "&&", "")
        runCommand = runCommand.replace("%t", instrumentedBinary)
        if not testCommand(runCommand, 60):
            print("Test: " + testFile)
            print("\tCommand failed")
            invalid.append(testFile)
            failed = failed + 1
            return

    print("Tests in: " + testFile + " succeeded")

workQueue = []
for subdir in testSubDirectories:
    fullTestDirectory = os.path.join(testDirectory, subdir)
    for filename in os.listdir(fullTestDirectory):
        f = os.path.join(fullTestDirectory, filename)
        if os.path.isfile(f) and (f.endswith(".cpp") or f.endswith(".c")):
            if len(runOnly) > 0 and not filename in runOnly:
                continue
            if f in exclude:
                continue
            workQueue.append(os.path.join(subdir, filename))
workQueue.sort()


class workerThread (threading.Thread):
    def __init__(self, q, lock):
        threading.Thread.__init__(self)
        self.q = q
        self.lock = lock
    def run(self):
        while True:
            queueLock.acquire()
            if len(self.q) > 0:
                f = self.q.pop(0)
                queueLock.release()
                checkFile(f)
            else:
                queueLock.release()
                return
        

queueLock = threading.Lock()
threads = []
for i in range(numThread):
   thread = workerThread(workQueue, queueLock)
   thread.start()
   threads.append(thread)

for t in threads:
   t.join()

print("\n\n\nProblems: " + str(invalid))
print("Failed " + str(failed) + " out of " + str(total) + " tests")
if setupFailed > 0:
    print("The basic setup failed in " + str(setupFailed) + " cases")
if compilerTSanFailed > 0:
    print("The compiler thread sanitizer failed in " + str(compilerTSanFailed) + " cases")

if failed > 0:
    exit(1)
exit(0)
