import os
import subprocess
import sys
import re
import threading
import filecheck
import shutil
import glob

if len(sys.argv) != 3:
    print("Usage: python3 " + sys.argv[0] + " thread-sanitizer-script output-folder")
    quit()

numThread = 3

tsandir = os.path.realpath("../tests/openmp/")
outputdir = os.path.realpath(sys.argv[2])
runScript = os.path.realpath(sys.argv[1])

os.chdir(outputdir)

exclude = []
runOnly = []

invalid = []

total = 0
failed = 0
setupFailed = 0

libraryName = "/usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0"
libOutName = os.path.realpath("instrumented-libraries/libgomp.so.1.0.0")
copiedLibraryName = os.path.realpath("libgomp-copy.so")
libPath = os.path.realpath("instrumented-libraries")
print("Instrumenting library " + libraryName)
if not os.path.isdir(libPath):
    print("Creating the instrumented libraries folder: " + libPath)
    os.mkdir(libPath)
shutil.copy(libraryName, copiedLibraryName)
res = subprocess.run([runScript, copiedLibraryName, libOutName, "--atomics-only"], capture_output=True)
if res.returncode != 0:
    print("\tInstrumenting the library libgomp.so failed:")
    print(str(res.stdout).replace("\\n", "\n"))
    print(str(res.stderr).replace("\\n", "\n"))
    exit(1)
# TODO: create the symlinks

def checkFile(filename):
    global total
    global failed
    global setupFailed
    f = os.path.join(tsandir, filename)
    outfile = os.path.join(outputdir, filename.split("/")[-1].replace(".cpp", "").replace(".c", ""))
    
    res = subprocess.run(["gcc", "-fopenmp", "-O2", f, "-o", outfile], capture_output=True)
    if res.returncode != 0:
        setupFailed = setupFailed + 1
        print("Test: " + filename)
        print("\tFailed to compile " + filename)
        return
    
    instrumentedBinary = outfile + "-mod"
    res = subprocess.run([runScript, outfile, instrumentedBinary], capture_output=True)
    if res.returncode != 0:
        print("Test: " + filename)
        print("\tInstrumenting the binary failed:")
        print(str(res.stdout).replace("\\n", "\n"))
        print(str(res.stderr).replace("\\n", "\n"))
        invalid.append(filename)
        failed = failed + 1
        total = total + 1
        return
    
    total = total + 1
    for i in range(1):
        try:
            environmentVariables = dict(os.environ)
            environmentVariables["LD_LIBRARY_PATH"] = libPath
            res2 = subprocess.run([instrumentedBinary], env=environmentVariables, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        except:
            print("Test: " + filename)
            print("\tInstrumented binary timed out!")
            invalid.append(filename)
            failed = failed + 1
            return
        
        if res2.returncode != 0:
            break
        
    res = filecheck.checkLines(f, str(res2.stdout).split("\\n"))
    if res[0] != 0:
        print("Test: " + filename)
        print("\t" + res[1])
        invalid.append(filename)
        failed = failed + 1
        return

    print("Tests in: " + filename + " succeeded")

workQueue = []
for filename in glob.iglob(tsandir + '/**/*.c', recursive=True):
    f = os.path.join(tsandir, filename)
    if os.path.isfile(f) and (f.endswith(".cpp") or f.endswith(".c")):
        if len(runOnly) > 0 and not filename in runOnly:
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
