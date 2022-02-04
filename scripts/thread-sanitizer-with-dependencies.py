import sys
import os
import subprocess
import shutil

if len(sys.argv) != 4:
    print("Usage: python3 " + sys.argv[0] + " build-folder binary-in binary-out")
    exit(1)

binaryFolder = sys.argv[1]
if not os.path.isdir(binaryFolder):
    print("First argument must be a folder")
    exit(1)


LIBRARY_WHITELIST = ["libglib-2.0.so", "libxcb.so", "libdbus-1.so", "libQt5Core.so", "libQt5DBus.so", "libQt5Widgets.so", "libQt5XcbQpa.so"]

ADDITIONAL_DEPENDENCIES = [ ["libQt5Core.so", ["libQt5DBus.so.5"]] ]


instrumentedBinariesFolder = os.path.join(binaryFolder, "instrumented-libraries")
instrumentedBinariesFolder = os.path.realpath(instrumentedBinariesFolder)
threadSanitizerScript = os.path.join(binaryFolder, "thread-sanitizer.sh")
inputBinary = sys.argv[2]
outputBinary = sys.argv[3]


def findSharedLibrary(name):
    whereisResult = subprocess.run(["whereis", name], capture_output=True)
    if whereisResult.returncode != 0:
        print("whereis failed!")
        return ""
    parts = str(whereisResult.stdout).split(" ")
    if len(parts) < 2 or len(parts[1]) < 5:
        print("Could not find shared library: " + name)
        return ""
    fullLibName = parts[1].replace("\\n", "").replace("'", "")
    if not ".so" in fullLibName:
        print("Not a .so file: " + fullLibName)
        return ""
    return fullLibName

def shouldBeInstrumented(library):
    for lib in LIBRARY_WHITELIST:
        if lib in library:
            return True
    return False

def librariesForBinary(binaryName):
    # TODO: (man ldd) You should never employ ldd on an untrusted executable, since this may result in the execution of arbitrary code
    res = subprocess.run(["ldd", binaryName], capture_output=True)
    if res.returncode != 0:
        os.system("ldd " + binaryName)
        print("ldd failed!")
        exit(1)

    librariesToInstrument = []
    for line in str(res.stdout).split("\\n"):
        if len(line) < 5:
            continue
        if len(line.split(" => ")) < 2:
            continue
        library = line.split(" => ")[1].split(" ")[0]
        
        if not shouldBeInstrumented(library):
            continue
        
        librariesToInstrument.append(library)
    
    return librariesToInstrument

if not os.path.isdir(instrumentedBinariesFolder):
    print("Creating the instrumented binary folder")
    os.mkdir(instrumentedBinariesFolder)

# search for additional dependencies loaded at run-time
toInstrument = librariesForBinary(inputBinary)
for lib in toInstrument:
    for testDep in ADDITIONAL_DEPENDENCIES:
        if testDep[0] in lib:
            for additionalDependency in testDep[1]:
                dbusName = findSharedLibrary(additionalDependency)
                if dbusName == "":
                    continue
                if shouldBeInstrumented(additionalDependency):
                    toInstrument.append(dbusName)
                toInstrument = toInstrument + librariesForBinary(dbusName)

# remove duplicates
toInstrument = list(dict.fromkeys(toInstrument))

for library in toInstrument:
    origLibrary = library.split("/")[-1]
    library = os.path.realpath(library)
    print("Instrument library " + library)
    
    origLibraryName = library.split("/")[-1]
    
    instrumentedOutput = os.path.join(instrumentedBinariesFolder, origLibraryName)
    if os.path.isfile(instrumentedOutput):
        print("\t-> Already exists, not instrumenting again!")
    else:
        # copy library temporarily since zipr aparently needs write access to protect the file
        copiedLibraryPath = os.path.join(instrumentedBinariesFolder, library.split("/")[-1] + "-temp")
        shutil.copy(library, copiedLibraryPath)
        
        exitcode = os.system(threadSanitizerScript + " " + copiedLibraryPath + " " + instrumentedOutput)
        if os.path.isfile("tsan-instrumentation-attribution.dat"):
            os.rename("tsan-instrumentation-attribution.dat", origLibrary + ".attribution")
        
        # delete copy of the original library
        os.remove(copiedLibraryPath)
        
        if exitcode != 0:
            print("\t-> Instrumenting the library failed, it will not be used")
            #exit(1)
            continue
        
    # create symbolic link for the different subversions
    libPart = instrumentedOutput.split(".so")[0]
    versionPart = "so" + instrumentedOutput.split(".so")[1]
    
    # TODO: this does not work with multiple different versions of the same library
    for part in versionPart.split("."):
        libPart = libPart + "." + part
        if not os.path.isfile(libPart):
            print("\tCreating symlink " + libPart)
            os.symlink(instrumentedOutput, libPart)
        
    
# instrument the executable
print("\nInstrumenting the target binary")

# copy the input binary, it might be write protected
inputBinaryTemp = os.path.join(instrumentedBinariesFolder, "input-temp")
shutil.copy(inputBinary, inputBinaryTemp)

# instrument the binary
exitcode = os.system(threadSanitizerScript + " " + inputBinaryTemp + " " + outputBinary)
if os.path.isfile("tsan-instrumentation-attribution.dat"):
    os.rename("tsan-instrumentation-attribution.dat", outputBinary + ".attribution")

os.remove(inputBinaryTemp)

if exitcode != 0:
    print("Instrumenting the executable failed!")
    exit(1)

print("\n\nInstrumenting successfull, please run the target binary like this:")
print("LD_LIBRARY_PATH=" + instrumentedBinariesFolder + " ./" + outputBinary)
print("or")
print("LD_LIBRARY_PATH=" + instrumentedBinariesFolder + " unbuffer ./" + outputBinary + " 2>&1 | " + binaryFolder + "/ps-plugin/translate-stacktrace")
