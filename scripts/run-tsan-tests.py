import os
import subprocess
import sys
import re
import threading

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " thread-sanitizer-script output-folder")
    quit()

numThread = 3
tsandir = os.path.realpath("../tests/llvm-tsan-tests")
outputdir = os.path.realpath(sys.argv[2])
runScript = os.path.realpath(sys.argv[1])

os.chdir(outputdir)

exclude = []
runOnly = []

invalid = []

total = 0
failed = 0
setupFailed = 0

def checkFile(filename):
    global total
    global failed
    global setupFailed
    f = os.path.join(tsandir, filename)
    outfile = os.path.join(outputdir, filename.replace(".cpp", "").replace(".c", ""))
    
    checkLines = []
    runLines = []
    for line in open(f, "r").readlines():
        if "// RUN: " in line:
            runLines.append(line)
        if "// CHECK: " in line or "// CHECK-NOT: " in line:
            checkLines.append(line)
    
    for line in runLines:
        p1 = line.split("&&")[0]
        p1 = p1.replace("// RUN: ", "").replace("\n", "")
        if "lang" in p1:
            p1 = p1.replace("%s", f)
            c1 = p1.replace("%t", outfile)
            c1 = c1.replace("%clang_tsan", "clang -lpthread -ltsan")
            c1 = c1.replace("%clangxx_tsan", "clang -lpthread -ltsan -lstdc++")
            c2 = p1.replace("%t", outfile + "-thread")
            c2 = c2.replace("%clang_tsan", "clang -fsanitize=thread")
            c2 = c2.replace("%clangxx_tsan", "clang -fsanitize=thread -lstdc++")
            
            if not "%" in c1 and not "%" in c2:
                res = subprocess.run(c1.split(" "), capture_output=True)
                if res.returncode != 0:
                    setupFailed = setupFailed + 1
                    print("Test: " + filename)
                    print("\tFailed to compile " + filename)
                    return
                res = subprocess.run(c2.split(" "), capture_output=True)
                if res.returncode != 0:
                    setupFailed = setupFailed + 1
                    print("Test: " + filename)
                    print("\tFailed to compile " + filename)
                    return
                if not os.path.isfile(outfile): # might be compiled to a shared library
                    setupFailed = setupFailed + 1
                    print("Test: " + filename)
                    print("\tThe compilation result is not an executable")
                    return
                instrumentedBinary = outfile + "-mod"
                res = subprocess.run([runScript, outfile, instrumentedBinary], capture_output=True)
                if res.returncode != 0:
                    print("Test: " + filename)
                    print("\tInstrumenting the binary failed:")
                    print(res.stdout)
                    print(res.stderr)
                    quit()
                
                try: 
                    res1 = subprocess.run([outfile + "-thread"], capture_output=True, timeout=30)
                except:
                    print("Test: " + filename)
                    print("\tCompiler thread sanitized binary timed out!")
                    return
                try:
                    res2 = subprocess.run([outfile + "-mod"], capture_output=True, timeout=30)
                except:
                    print("Test: " + filename)
                    print("\tInstrumented binary timed out!")
                    invalid.append(filename)
                    failed = failed + 1
                    return
                
                total = total + 1
                if res1.returncode != res2.returncode:
                    invalid.append(filename)
                    failed = failed + 1
                    print("Test: " + filename)
                    print("\tFailed (got exitcode " + str(res2.returncode) + ", expected " + str(res1.returncode) + ")!")
                    return

                # TODO: also run the other tests in the file
                print("Test: " + filename + " succeeded")
                return

workQueue = []
for filename in os.listdir(tsandir):
    f = os.path.join(tsandir, filename)
    if os.path.isfile(f) and (f.endswith(".cpp") or f.endswith(".c")):
        if len(runOnly) > 0 and not f in runOnly:
            continue
        if f in exclude:
            continue
        workQueue.append(filename)
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

if failed > 0:
    exit(1)
exit(0)
