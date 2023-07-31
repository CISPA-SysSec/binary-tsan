#! /usr/bin/python3

#DONE: seperate running and interpretation better
#DONE: add Helgrind support
#TODO: enhance automatic interpretation

import os
import shutil
import subprocess
import sys
import time
import pickle
from concurrent.futures import ThreadPoolExecutor
from statistics import mean, median, variance, stdev

#CONFIGURATION

#base config

#base path where data is located
PATH = "./"
#force overwrite of existing data
DO_OVERWRITE = False
#number of threads
MAXWORKERS = 16
#limit number of processed input (0: no limit)
LIMIT_INPUTS = 0
#which categories are tested; supported: .san (bintsan), .tsan (tsan), .hel (helgrind), ".noatom" (bintsan without atomic instrum)
ENDINGS = [".tsan", ".san", ".noatom"]#, ".tsan", ".hel"]#, ".noatom"]

#execution config
FUZZTARGETS = [
        #["pigz/res_1c_13r_pigz_1", "-cdk -p 4 @@"],
        #["pbz2/res_1c_13r_pbzip2_1", "-cdkr @@"],
        #["xz/res_1c_13r_xz_1", "-c --threads=3 @@"],
        ["unrar/res_1c_13r_unrar_1", "p -mt7 -r @@"],
        #["lrzip/res_1c_13r_lrzip_1", "-dfQ -O /tmp/ @@"],
        #["ffmpeg_g/res_1c_13r_ffmpeg_1", "-i @@ -f avi pipe:1"]
    ]

#timeout per execution
TIMEOUT_LIMIT = 1#60*60*7 #in seconds
#do not process new data, only used already existing files
ONLY_USE_EXISTING_DATA = False
ONLY_USE_EXISTING_DATA_IF_BOTH = False

#number of repetitions for each target
NUMBER_OF_CYCLES = 3
#report status every nth target
REPORTINGINTERVAL = 20


#fingerprint and filtering config

#detection string for data race warnings in bintsan/tsan and helgrind
DATARACE_DETECTION_STRING = "WARNING: ThreadSanitizer: data race"
DATARACE_DETECTION_STRING_HELGRIND = "Possible data race during"

FINGERPRINT_DEDUPLICATE_FUNCTIONNAMEENTRIES = True
FINGERPRINT_BLANK_SIZE = True
FINGERPRINT_LIMIT_STACKTRACE_LENGTH = 1 #0: add full stack trace;

FINGERPRINT_FFMPEG_FILTERS = True

#output formating
SHOW_ACTUAL_FINGERPRINTS = False
PRINT_CYCLE_RESULTS = False
PRINT_CYCLE_DEVIATION = True

# PROGRAM

def copyAllFromFolder(type, source, destination):
    #print("copyAll:"+source)
    files = os.listdir(source)
    files.sort()
    for file_name in files:
        #print("file: "+file_name)
        sourcefile = source + file_name
        destinationfile = destination + type + "_" + file_name
        # copy only files
        if os.path.isfile(sourcefile):
            #print("src: "+sourcefile)
            #print("dst: "+destinationfile)
            shutil.copy(sourcefile, destinationfile)

def prepare(respath):

    outputDir = respath+"/OutputLogs/" 
    if not os.path.isdir(outputDir):
        os.mkdir(outputDir)

    outputDirSerialized = respath+"/OutputLogsSerialized/" 
    if not os.path.isdir(outputDirSerialized):
        os.mkdir(outputDirSerialized)

    queueDir = respath+"/totalQueue/" 
    if not os.path.isdir(queueDir):
        os.mkdir(queueDir)
    else:
        if(DO_OVERWRITE):
            shutil.rmtree(queueDir)
            os.mkdir(queueDir)
        else:
            print("Skipped copying files to "+queueDir+" as it does already exist")
            return
    
    #copy queues:

    types = {"afl", "bintsan", "tsan", "zafl"}
    directories = {"queue", "hangs", "crashes"}

    for i in range(1, 14):
        number = str(i)
        if(i<10):
            number = "0"+number
        #print(number)
        for dir in directories:
            for type in types:
                srcdir = respath+"/"+type+"/"+number+"/default/"+dir+"/"
                #print(srcdir)
                copyAllFromFolder(type+"_"+number+"_"+dir, srcdir, queueDir)


    print("files copied to "+queueDir)

def minimize(respath, arguments):
    path = respath.split("/")[0]
    testcase = respath.split("/")[1]

    if os.path.isdir(respath+"/totalQueue_min"):
        if DO_OVERWRITE:
            shutil.rmtree(respath+"/totalQueue_min")
        else:
            print("Skipping minimization as "+respath+"/totalQueue_min does already exist")
            return
    
    os.system("afl-cmin -i "+respath+"/totalQueue -o "+respath+"/totalQueue_min -- "+path+"/"+testcase+"/files/"+testcase+".afl "+arguments)

    print(testcase+" minimized")


def getNextWordAfterKey(key, string):
    words = string.split(" ")

    for i in range (0, len(words)):
        curr = words[i]
        if(curr == key):
            if(i+1 < len(words)):
                return words[i+1]
            
    print("ERROR: value not found for key word '"+key+"' in word:"+string)
    return None

def printErrorMessage(message):
    (created, previous, race, createdStacktrace, previousStacktrace, raceStacktrace) = message

    (optype, thread, locationBinary, size) = race
    print(optype+" of size "+str(size)+" in thread "+thread+" at "+locationBinary)
    
    for entry in raceStacktrace:
        (functionName, locationBinary) = entry
        print(functionName+ ""+locationBinary+"")

    (optype, thread, locationBinary, size) = previous
    print("Conflicts with previous "+optype+" of size "+str(size)+" in thread "+thread+" at "+locationBinary)

    for entry in previousStacktrace:
        (functionName, locationBinary) = entry
        print(functionName+ ""+locationBinary+"")
    #(location, locationBinary) = created

    
def fingerPrintRace(racedata):

    #print(racedata)

    fingerprint = ""

    fingerprint += "race:"

    (created, previous, race, createdStacktrace, previousStacktrace, raceStacktrace) = racedata

    (optype, thread, locationBinary, size) = race

    if(FINGERPRINT_BLANK_SIZE):
        size = "X"

    fingerprint += optype+";"+size+";"#+thread+";"

    lastfunctionname = ""

    if(FINGERPRINT_LIMIT_STACKTRACE_LENGTH > 0):
        raceStacktrace = raceStacktrace[:FINGERPRINT_LIMIT_STACKTRACE_LENGTH]
    
    for entry in raceStacktrace:
        (functionName, locationBinary) = entry


        if(FINGERPRINT_FFMPEG_FILTERS):
            if("put_h264_qpel16_mc" in functionName):
                functionName = "put_h264_qpel16_mcXX_9_c"
            elif("put_h264_qpel8_mc" in functionName):
                functionName = "put_h264_qpel8_mcXX_9_c"
            elif("put_h264_qpel4_mc" in functionName):
                functionName = "put_h264_qpel4_mcXX_9_c"
            elif("avg_h264_qpel4_mc" in functionName):
                functionName = "avg_h264_qpel4_mcXX_9_c"
            elif("avg_h264_qpel8_mc" in functionName):
                functionName = "avg_h264_qpel8_mcXX_9_c"
            elif("avg_h264_qpel16_mc" in functionName):
                functionName = "avg_h264_qpel16_mcXX_9_c"
                

        if(functionName != lastfunctionname or (not FINGERPRINT_DEDUPLICATE_FUNCTIONNAMEENTRIES)):
            fingerprint += functionName+"<-"
            lastfunctionname = functionName

    fingerprint += "previous:"
    #print(previous)
    (optype, thread, locationBinary, size) = previous

    if(FINGERPRINT_BLANK_SIZE):
        size = "X"

    fingerprint += optype+";"+size+";"#+thread+";"


    lastfunctionname = ""

    if(FINGERPRINT_LIMIT_STACKTRACE_LENGTH > 0):
        previousStacktrace = previousStacktrace[:FINGERPRINT_LIMIT_STACKTRACE_LENGTH]

    for entry in previousStacktrace:
        (functionName, locationBinary) = entry

        if(FINGERPRINT_FFMPEG_FILTERS):
            if("put_h264_qpel16_mc" in functionName):
                functionName = "put_h264_qpel16_mcXX_9_c"
            elif("put_h264_qpel8_mc" in functionName):
                functionName = "put_h264_qpel8_mcXX_9_c"
            elif("put_h264_qpel4_mc" in functionName):
                functionName = "put_h264_qpel4_mcXX_9_c"
            elif("avg_h264_qpel4_mc" in functionName):
                functionName = "avg_h264_qpel4_mcXX_9_c"
            elif("avg_h264_qpel8_mc" in functionName):
                functionName = "avg_h264_qpel8_mcXX_9_c"
            elif("avg_h264_qpel16_mc" in functionName):
                functionName = "avg_h264_qpel16_mcXX_9_c"

        if(functionName != lastfunctionname or (not FINGERPRINT_DEDUPLICATE_FUNCTIONNAMEENTRIES)):
            fingerprint += functionName+"<-"
            lastfunctionname = functionName

    #print(fingerprint)
    if(FINGERPRINT_FFMPEG_FILTERS):
        if(fingerprint.endswith("frame_worker_thread<-")):
            fingerprint = fingerprint[:-len("frame_worker_thread<-")]
        if(fingerprint.endswith("main<-")):
            fingerprint = fingerprint[:-len("main<-")]

    while("<-<-" in fingerprint):
        fingerprint = fingerprint.replace("<-<-", "<-")
    
    return fingerprint

def parseOutputHelgrind(output):
    dataRaceData = list()

    #print(output)

    dataRaces = output.split(DATARACE_DETECTION_STRING_HELGRIND)
    dataRaces = dataRaces[1:]
    #print(dataRaces)
    for raceLogEntry in dataRaces:
        raceLogEntry = "==13371337=="+DATARACE_DETECTION_STRING_HELGRIND+raceLogEntry

        lines = raceLogEntry.split("\\n")
        #skip created, as this is not simple to parse in helgrind logs and currently not needed
        createdStacktrace = list()
        created = list()

        previousStacktrace = list()
        raceStacktrace = list()


        previous = []
        race = []
        skipThisDataRace = False

        previousLine = ""



        stackTraceMode = ""
        stackTraceEntryCounter = 0
        createdStackTraceReached = False

        #print(raceLogEntry)

        for line in lines:
            #line preprocessing
            if("==" not in line):
                continue
            lineparts = line.split("==")
            if(len(lineparts) != 3):
                #print("WARNING: HelgrindParser wrong line format")
                #print(line)
                #print(raceLogEntry)
                continue
                #sys.exit()
            line = lineparts[2].strip()

            if("This conflicts with a previous" in line):
                stackTraceMode = "previous"
                stackTraceEntryCounter = 0                
                optype = getNextWordAfterKey("previous", line)
                thread = getNextWordAfterKey("thread", line)
                locationBinary = "NotImplemented" #getNextWordAfterKey("address", line)
                size = getNextWordAfterKey("size", line)

                previous = (optype, thread, locationBinary, size)
            elif(("bytes inside a block of size" in line) and ("Address" in line)):
                pass
                '''
                stackTraceMode = "previous"
                stackTraceEntryCounter = 0                
                optype = "alloc"#"alloc"
                #TODO: handle the alloc case better
                thread = "NotImplemented"#getNextWordAfterKey("thread", line)
                locationBinary = getNextWordAfterKey("Address", line)
                size = getNextWordAfterKey("size", line)

                previous = (optype, thread, locationBinary, size)
                '''
            elif("Possible data race during" in line):
                #actual race
                stackTraceMode = "race"
                stackTraceEntryCounter = 0
                optype = getNextWordAfterKey("during", line)
                thread = getNextWordAfterKey("thread", line)
                locationBinary = "NotImplemented" #getNextWordAfterKey("address", line)
                size = getNextWordAfterKey("size", line)
                race = (optype, thread, locationBinary, size)

            
            elif(("at 0x" in line) or ("by 0x" in line)):
                #line of stack trace
                #stacktrace entry
                words = line.strip().split(" ")

                if(len(words) >= 3):
                    functionName = cleanParseFunctionName(words[2])
                    locationBinary = words[1]
                    dataEntry = (functionName, locationBinary)
                    if(stackTraceMode == "previous"):
                        previousStacktrace.append(dataEntry)
                        stackTraceEntryCounter += 1
                    elif(stackTraceMode == "race"):
                        raceStacktrace.append(dataEntry)
                        stackTraceEntryCounter += 1
                    else:
                        print("ERROR: no stackTraceMode selected")
                        print(line+"\n\n")
                        print(raceLogEntry)
                        #print(output)
                        sys.exit()
                else:
                    print("ERROR: wrong line interpreted as stacktrace line!")

            elif("----------------------------------------------------------------" in line):
                break


        if(len(race) != 4):
            continue
        
        if(len(previous) != 4):
            #print("WARNING: Helgrind has no conflict info (previous)")
            #print((created, previous, race))
            #print(raceLogEntry)
            continue
        
        result = (created, previous, race, createdStacktrace, previousStacktrace, raceStacktrace)
        
        #print(raceLogEntry)
        #print(result)
        #print("\n\n")
        fingerprint = fingerPrintRace(result)        
        #print(fingerprint)
        #sys.exit()
        #print(raceLogEntry)
        dataRaceData.append((fingerprint, result, raceLogEntry))

    return dataRaceData

def cleanParseFunctionName(functionName):
    if("(" in functionName):
        functionName = functionName.split('(')[0]

    if(">" in functionName):
        functionName = functionName.split('>')
        functionName = functionName[len(functionName)-1]
    return functionName

def parseOutput(output):

    dataRaceData = list()

    #print(output)
    dataRaces = output.split(DATARACE_DETECTION_STRING)
    dataRaces = dataRaces[1:]
    for raceLogEntry in dataRaces:
        raceLogEntry = DATARACE_DETECTION_STRING+raceLogEntry
        lines = raceLogEntry.split("\\n")
        createdStacktrace = list()
        previousStacktrace = list()
        raceStacktrace = list()

        created = []
        previous = []
        race = []
        skipThisDataRace = False

        previousLine = ""



        stackTraceMode = ""
        stackTraceEntryCounter = 0
        createdStackTraceReached = False #shows if the last stack trace has been reached => after that parsing is stopped to avoid conflict with other tsan messages
        #print(lines)
        for line in lines:
            line = line.strip()

            if("thread leak" in line):
                skipThisDataRace = True
                break
            elif(("As if synchronized via sleep:" in line)):
                stackTraceMode = "syncVia"
                stackTraceEntryCounter = 0
            elif(("Location is" in line)):
                #Location (next line-> creation)
                location = getNextWordAfterKey("is", line)
                locationBinary = getNextWordAfterKey("at", line)
                created = (location, locationBinary)
                stackTraceMode = "creation"
                stackTraceEntryCounter = 0
            elif(("created" in line)):
                #creation
                stackTraceMode = "creation"
                stackTraceEntryCounter = 0
            elif("of size" in line):
                if("Previous" in line):
                    stackTraceMode = "previous"
                    stackTraceEntryCounter = 0

                    optype = line.strip().split(" ")[1].lower()
                    if("main" in line):
                        thread = "main"
                    else:
                        thread = getNextWordAfterKey("thread", line)
                    locationBinary = getNextWordAfterKey("at", line)
                    size = getNextWordAfterKey("size", line)
                    previous = (optype, thread, locationBinary, size)

                elif("Truncating packet" in line):
                    continue
                else:


                    #actual race
                    stackTraceMode = "race"
                    stackTraceEntryCounter = 0

                    optype = line.strip().split(" ")[0].lower()
                    if("main" in line):
                        thread = "main"
                    else:
                        thread = getNextWordAfterKey("thread", line)
                    locationBinary = getNextWordAfterKey("at", line)
                    size = getNextWordAfterKey("size", line)
                    race = (optype, thread, locationBinary, size)

            elif("#" in line):
                parts = line.split("#")
                parts = parts[1:]

                for line in parts:

                    #stacktrace entry

                    words = line.strip().split(" ")
                    numberStr = words[0]

                    if(not numberStr.isnumeric()):
                        #print("ERROR: numberStr of Stacktrace is not numeric!")
                        #print(numberStr)
                        #print(line)
                        continue
                    else:
                        line = "#"+line
                        if(stackTraceMode == "syncVia"):
                            continue

                        currentEntryNumber = int(numberStr)

                        if(currentEntryNumber != stackTraceEntryCounter):
                            print("ERROR: interpreting stacktrace: wrong number! Found: "+str(currentEntryNumber)+"Expected: "+str(stackTraceEntryCounter))
                            print(line)
                            print(previousLine)
                            print(raceLogEntry)
                            sys.exit()

                        if(len(words) >= 4):
                            #functionName = words[1]

                            #counter = 0
                            #if("thread_entry" not in words[1]):
                            #    for word in words[1:]:
                            #        if(("(") in word):
                            #            break
                            #        counter += 1

                            functionName = words[1]
                            functionName = cleanParseFunctionName(functionName)
                            locationBinary = words[3]

                            dataEntry = (functionName, locationBinary)
                            if(stackTraceMode == "creation"):
                                createdStacktrace.append(dataEntry)
                                createdStackTraceReached = True
                                stackTraceEntryCounter += 1
                            elif(stackTraceMode == "previous"):
                                previousStacktrace.append(dataEntry)
                                stackTraceEntryCounter += 1
                            elif(stackTraceMode == "race"):
                                raceStacktrace.append(dataEntry)
                                stackTraceEntryCounter += 1
                            else:
                                print("ERROR: no stackTraceMode selected")
                                print(line+"\n\n")
                                print(raceLogEntry)
                                #print(output)
                                sys.exit()
                        else:
                            print("ERROR: wrong line interpreted as stacktrace line!")
            
            else:
                
                #stackTraceMode = ""
                if(createdStackTraceReached):
                    #if the last stackTrace of this message has finished, break the loop to avoid parsing other messages, like thread leaks
                    break
            
            previousLine = line
        if(skipThisDataRace or len(created) == 0):
            continue
        
        result = (created, previous, race, createdStacktrace, previousStacktrace, raceStacktrace)
        fingerprint = fingerPrintRace(result)        
        #print(result)
        #print(raceLogEntry)
        dataRaceData.append((fingerprint, result, raceLogEntry))
    return dataRaceData

def executeCommand(input):

    (counter, numOfExecs, cycle, file_name, ending, command, respath) = input
    
    percentageDone = round((counter/numOfExecs)*100)
    
    outputDir = respath+"/OutputLogs/" 

    if(cycle > 1):
        ending = ending + str(cycle)

    logFilePath = outputDir+file_name+ending

    # print(logFilePath)
    
    if(ONLY_USE_EXISTING_DATA_IF_BOTH):
        if((not os.path.isfile(outputDir+file_name+".tsan")) or (not os.path.isfile(outputDir+file_name+".san"))):
            
            if(not os.path.isfile(outputDir+file_name+".tsan")):
               print(".tsan missing for file: "+file_name)

            if(not os.path.isfile(outputDir+file_name+".san")):
               print(".san missing for file: "+file_name)

            if(respath+"/totalQueue_min/"+file_name):
                print("removed "+file_name)
                shutil.move(respath+"/totalQueue_min/"+file_name, respath+"/totalQueue_notConsidered/"+file_name)
            
            return None                    
                        

    if((not os.path.isfile(logFilePath)) or DO_OVERWRITE):
        #no logfile exists, execute program
  
        #proc = subprocess.Popen(" ".join(command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #out, err = proc.communicate()

        if(ONLY_USE_EXISTING_DATA):
            return None
        
        #print(command)
        try:
            result = subprocess.run(command, capture_output=True, timeout=TIMEOUT_LIMIT)
        except subprocess.TimeoutExpired:
            print("WARNING: "+file_name+" timed out for process with ending: '"+ending+"'!")
            return None

        err = result.stderr

        f = open(logFilePath, "wb")
        f.write(err)
        f.close()

    if(counter % REPORTINGINTERVAL == 0):#only print every xth status update
                    print(str(percentageDone)+"% done ["+str(counter)+"/"+str(numOfExecs)+"] of executing")

    return None

def getResult(input):
    (counter, numOfExecs, cycle, file_name, ending, command, respath) = input

    percentageDone = round((counter/numOfExecs)*100)
    
    outputDir = respath+"/OutputLogs/"
    serialzedDir = respath+"/OutputLogsSerialized/" 

    if(cycle > 1):
        ending = ending + str(cycle)

    logFilePath = outputDir+file_name+ending
    serialzedFilePath = serialzedDir+file_name+ending

    filters = [
            "is NOT a valid bzip2!",
            "Data integrity (CRC) error in data!",
            "ERROR: File ends unexpectedly!"
        ]
    
    #if serialized => get that data
    if(os.path.isfile(serialzedFilePath)):
        '''
        with open(serialzedFilePath, "rb") as infile:
            data = pickle.load(infile)

            
            if(counter % REPORTINGINTERVAL == 0):#only print every xth status update
                        print(str(percentageDone)+"% done ["+str(counter)+"/"+str(numOfExecs)+"] of parsing")

            return (file_name, ending, data)
        '''
    if(os.path.isfile(logFilePath)):
        #logfile already exists, use logfile instead
        f = open(logFilePath, "rb")
        err = f.read()
        f.close()
    
        if(err):
            if(err != ""):
                err = str(err)
                #print("err: "+err)
                #if("ERROR" in err or "ThreadSanitizer" in err):
                if(DATARACE_DETECTION_STRING in err or DATARACE_DETECTION_STRING_HELGRIND in err):
                    for filter in filters:
                        if(filter in err):
                            return None

                    #print("err: "+str(result.stderr))
                    if(".hel" in ending):
                        data = parseOutputHelgrind(err)
                    else:
                        data = parseOutput(err)

                    if(data is None):
                        return None

                    #if(counter % REPORTINGINTERVAL == 0):#only print every xth status update
                    #    print(str(percentageDone)+"% done ["+str(counter)+"/"+str(numOfExecs)+"] of parsing")

                    #only dump data if file does not exist yet
                    '''
                    if(not os.path.isfile(serialzedFilePath)):
                        with open(serialzedFilePath, "wb") as outfile:
                            pickle.dump(data, outfile)
                    '''

                    return (file_name, ending, data)



def filter_fingerprints(fingerprints):
    #remove duplicates
    fingerprints = list(set(fingerprints))
    fingerprints.sort()

    return fingerprints

def calculateFalsePositivesAndNegatives(tsanFingerprints, bintsanFingerprints):

    print("Calculating fp/fn")

    matches = list()
    falsePositives = list()
    falseNegatives = list()

    for tsanFing in tsanFingerprints:
        if(tsanFing in bintsanFingerprints):
            matches.append(tsanFing)
        else:
            falseNegatives.append(tsanFing)
            
    
    for bintsanFing in bintsanFingerprints:
        if(bintsanFing not in tsanFingerprints):
            falsePositives.append(bintsanFing)
        

    print("Matches: "+str(len(matches)))

    if(SHOW_ACTUAL_FINGERPRINTS):
        for m in matches:
            print(m)
    
    print("FP: "+str(len(falsePositives)))
    
    if(SHOW_ACTUAL_FINGERPRINTS):
        for fp in falsePositives:
            print(fp)
    
    print("FN: "+str(len(falseNegatives)))

    if(SHOW_ACTUAL_FINGERPRINTS):
        for fn in falseNegatives:
            print(fn)

    return (falsePositives, falseNegatives)

def getErrorMessageByFingerprint(fingerprint_needle, fullErrors):

    for error in fullErrors:
        (file_name, ending, data) = error
        (fingerprint, rawdata, originalmessage) = data
        if(fingerprint == fingerprint_needle):
            return originalmessage
    
    print("ERROR: Fingerprint could not be matched to existing message")
    return None

def runAgainstPrograms(respath, arguments):
    path = respath.split("/")[0]
    testcase = respath.split("/")[1]

    #create queue of needed executions

    queueMinPath = respath+"/totalQueue_min/"
    inputs = os.listdir(queueMinPath)
    inputs.sort()
    
    if(LIMIT_INPUTS > 0):
        inputs = inputs[:LIMIT_INPUTS]

    execs = list()

    numOfExecs = NUMBER_OF_CYCLES*len(ENDINGS)*len(inputs)
    counter = 0

    for cycle in range(1, NUMBER_OF_CYCLES+1):
        for ending in ENDINGS:        
            for file_name in inputs:
                if(ending == ".hel"):
                    # -conflict-cache-size=150000000
                    command = "valgrind --track-lockorders=no --tool=helgrind --history-level=full "+path+"/"+testcase+"/files/"+testcase+" "+arguments
                else:
                    command = path+"/"+testcase+"/files/"+testcase+ending+" "+arguments
                executable = queueMinPath + file_name
                if os.path.isfile(executable):
                    command = command.replace("@@", executable)
                    #print(command)
                    excom = command.split(" ")
                    execs.append((counter, numOfExecs, cycle, file_name, ending, excom, respath))
                    counter+=1
                else:
                    print("WARNING: Skipped, because file is missing: "+executable)
                
    
    with ThreadPoolExecutor(max_workers = MAXWORKERS) as executor:
        #process queue => get results
        executor.map(executeCommand, execs)

    return execs


def cleanAndFormatResults(fullResult):

    resultsNew = list()

    #remove broken results
    for result in fullResult:
        #Remove Nones
        if (result is None):
            continue
        
        #detect broken results
        if((len(result) != 3)):
            print("ERROR: result with size != 3")
            print((len(result)))
            print(result)
            continue
        
        (file_name, ending, data) = result
        
        #print(len(data))

        for d in data:
        
            (fingerprint, rawdata, originalmessage) = d

            resultsNew.append((file_name, ending, fingerprint, rawdata, originalmessage))
    del fullResult

    return resultsNew
            
def getFingerprints(results):
    fingerprints = list()
    for res in results:
        (file_name, ending, fingerprint, rawdata, originalmessage) = res
        fingerprints.append(fingerprint)
    return fingerprints

def printFingerprints(fingerprints, type):
    #if(len(fingerprints) == 0):
    #    return
    print(type+": ")
    print("Unique data races: "+str(len(fingerprints)))

def getCycleResults(results):
    #print(results)
    fingerprints = getFingerprints(results)
    fingerprints = filter_fingerprints(fingerprints)
    return fingerprints
    

def measureCycleUncertain(fingerprintCycles, type):

    print(type+": ")

    numbers = list()
    for cycle in range(0, NUMBER_OF_CYCLES):
        if(len(fingerprintCycles[cycle]) == 0):
            print("/\n\n")
            return
        uniques = len(fingerprintCycles[cycle])
        numbers.append(uniques)
        
    print("Maximum: "+str(max(numbers)))
    print("Minimum: "+str(min(numbers)))
    print("Avg: "+str(mean(numbers)))
    print("Median: "+str(median(numbers)))
    #print("Variance: "+str(variance(numbers)))
    print("StdDev: "+str(stdev(numbers)))
    print("\n")

def parseResults(respath, arguments, execs):
        
        #TODO: change this to reflect actual processed inputs with logs, not theoretical number of inputs
        queueMinPath = respath+"/totalQueue_min/"
        inputs = os.listdir(queueMinPath)
        inputs.sort()

        if(LIMIT_INPUTS > 0):
            inputs = inputs[:LIMIT_INPUTS]

        print("Parse Results")

        #init
        execsNoAtom = [None]*NUMBER_OF_CYCLES
        execsTSAN = [None]*NUMBER_OF_CYCLES
        execsBINTSAN = [None]*NUMBER_OF_CYCLES
        execsHelgrind = [None]*NUMBER_OF_CYCLES

        fingerprintsNoAtom = [None]*NUMBER_OF_CYCLES
        fingerprintsTSAN = [None]*NUMBER_OF_CYCLES
        fingerprintsBINTSAN = [None]*NUMBER_OF_CYCLES
        fingerprintsHelgrind = [None]*NUMBER_OF_CYCLES

        for cycle in range(0,NUMBER_OF_CYCLES):
            execsNoAtom[cycle] = list()
            execsTSAN[cycle] = list()
            execsBINTSAN[cycle] = list()
            execsHelgrind[cycle] = list()

            fingerprintsNoAtom[cycle] = list()
            fingerprintsTSAN[cycle] = list()
            fingerprintsBINTSAN[cycle] = list()
            fingerprintsHelgrind[cycle] = list()

        #print(execs)
        
        #split up execs
        for exec in execs:
            (counter, numOfExecs, cycle, file_name, ending, excom, respath) = exec
            cycle -= 1
            if(ending == ".noatom"):
                execsNoAtom[cycle].append(exec)
            elif(ending == ".tsan"):
                execsTSAN[cycle].append(exec)
            elif(ending == ".san"):
                execsBINTSAN[cycle].append(exec)
            elif(ending == ".hel"):
                execsHelgrind[cycle].append(exec)
        
        #get results each cycle at a time
        with ThreadPoolExecutor(max_workers = MAXWORKERS) as parserExecutor:
            for cycle in range(0,NUMBER_OF_CYCLES):

                print("Parsing cycle "+str((cycle+1)))

                if(len(execsTSAN[cycle]) != 0):
                    resultsTSAN = None
                    resultsTSAN = parserExecutor.map(getResult, execsTSAN[cycle])
                    resultsTSAN = cleanAndFormatResults(resultsTSAN)
                    print("TSAN...")
                    cycleResultsTSAN = getCycleResults(resultsTSAN)
                    fingerprintsTSAN[cycle] = cycleResultsTSAN
                    del resultsTSAN

                if(len(execsBINTSAN[cycle]) != 0):
                    resultsBINTSAN = None
                    resultsBINTSAN = parserExecutor.map(getResult, execsBINTSAN[cycle])
                    resultsBINTSAN = cleanAndFormatResults(resultsBINTSAN)
                    print("BINTSAN...") 
                    cycleResultsBINTSAN = getCycleResults(resultsBINTSAN)
                    fingerprintsBINTSAN[cycle] = cycleResultsBINTSAN
                    if(".tsan" in ENDINGS):
                        calculateFalsePositivesAndNegatives(fingerprintsTSAN[cycle], fingerprintsBINTSAN[cycle])
                    del resultsBINTSAN
                
                if(len(execsNoAtom[cycle]) != 0):
                    resultsNoAtom = None
                    resultsNoAtom = parserExecutor.map(getResult, execsNoAtom[cycle])
                    resultsNoAtom = cleanAndFormatResults(resultsNoAtom)
                    print("NoAtom...")
                    cycleResultsNoAtom = getCycleResults(resultsNoAtom)
                    fingerprintsNoAtom[cycle] = cycleResultsNoAtom
                    if(".tsan" in ENDINGS):
                        calculateFalsePositivesAndNegatives(fingerprintsTSAN[cycle], fingerprintsNoAtom[cycle])
                    del resultsNoAtom

                if(len(execsHelgrind[cycle]) != 0):
                    resultsHelgrind = None
                    resultsHelgrind = parserExecutor.map(getResult, execsHelgrind[cycle])
                    resultsHelgrind = cleanAndFormatResults(resultsHelgrind)
                    print("Helgrind...")
                    cycleResultsHelgrind = getCycleResults(resultsHelgrind)
                    fingerprintsHelgrind[cycle] = cycleResultsHelgrind
                    if(".tsan" in ENDINGS):
                        calculateFalsePositivesAndNegatives(fingerprintsTSAN[cycle], fingerprintsHelgrind[cycle])
                    del resultsHelgrind

                print("-----------------------------------------------------------------------------------")
        printResults(fingerprintsTSAN, fingerprintsBINTSAN, fingerprintsNoAtom, fingerprintsHelgrind)


def printResults(fingerprintsTSAN, fingerprintsBINTSAN, fingerprintsNoAtom, fingerprintsHelgrind):
        
    fingerprintsNoAtomAllCycles = list()
    fingerprintsTSANAllCycles = list()
    fingerprintsBINTSANAllCycles = list()
    fingerprintsHelgrindAllCycles = list()

    #add to All list and print results by cycle
    
    for cycle in range(0,NUMBER_OF_CYCLES):
        fingerprintsTSANAllCycles.extend(fingerprintsTSAN[cycle])
        fingerprintsBINTSANAllCycles.extend(fingerprintsBINTSAN[cycle])
        fingerprintsNoAtomAllCycles.extend(fingerprintsNoAtom[cycle])
        fingerprintsHelgrindAllCycles.extend(fingerprintsHelgrind[cycle])

        if(PRINT_CYCLE_RESULTS):
            print("Results cycle "+str((cycle+1))+":")
            
            printFingerprints(fingerprintsTSAN[cycle], "TSAN")
            printFingerprints(fingerprintsBINTSAN[cycle], "BINTSAN")
            if((".san" in ENDINGS) and (".tsan" in ENDINGS)):
                        calculateFalsePositivesAndNegatives(fingerprintsTSAN[cycle], fingerprintsBINTSAN[cycle])
            printFingerprints(fingerprintsNoAtom[cycle], "NoAtom")
            if((".noatom" in ENDINGS) and (".tsan" in ENDINGS)):
                        calculateFalsePositivesAndNegatives(fingerprintsTSAN[cycle], fingerprintsNoAtom[cycle])
            printFingerprints(fingerprintsHelgrind[cycle], "Helgrind")
            if((".hel" in ENDINGS) and (".tsan" in ENDINGS)):
                        calculateFalsePositivesAndNegatives(fingerprintsTSAN[cycle], fingerprintsHelgrind[cycle])
            print("-----------------------------------------------------------------------------------")

    print("-----------------------------------------------------------------------------------")
    #remove duplicates in between runs
    
    fingerprintsTSANAllCycles = filter_fingerprints(fingerprintsTSANAllCycles)
    fingerprintsBINTSANAllCycles = filter_fingerprints(fingerprintsBINTSANAllCycles)
    fingerprintsNoAtomAllCycles = filter_fingerprints(fingerprintsNoAtomAllCycles)
    fingerprintsHelgrindAllCycles = filter_fingerprints(fingerprintsHelgrindAllCycles)
    
    #get cycle uncertainty statistics
    if(PRINT_CYCLE_DEVIATION and NUMBER_OF_CYCLES > 1):
        print("Measuring Cycle Statistics:")
        #measureCycleUncertain(fingerprintsTSAN, "TSAN")
        measureCycleUncertain(fingerprintsBINTSAN, "BINTSAN")
        #measureCycleUncertain(fingerprintsNoAtom, "NoAtom")
        #measureCycleUncertain(fingerprintsHelgrind, "Helgrind")
    
    print("-----------------------------------------------------------------------------------")
    print("-----------------------------------------------------------------------------------")
    #print total results
    print("Combined Results:")
    #print("Total Inputs: "+str(len(inputs)))


    if(".noatom" in ENDINGS):
        printFingerprints(fingerprintsNoAtomAllCycles, "NoAtom")
        if(".tsan" in ENDINGS):
            calculateFalsePositivesAndNegatives(fingerprintsTSANAllCycles, fingerprintsNoAtomAllCycles)
        print("-----------------------------------------------------------------------------------")
    if(".tsan" in ENDINGS):
        printFingerprints(fingerprintsTSANAllCycles, "TSAN")
        print("-----------------------------------------------------------------------------------")
    if(".san" in ENDINGS):
        printFingerprints(fingerprintsBINTSANAllCycles, "BINTSAN")
        if(".tsan" in ENDINGS):
            calculateFalsePositivesAndNegatives(fingerprintsTSANAllCycles, fingerprintsBINTSANAllCycles)
            print("-----------------------------------------------------------------------------------")
    if(".hel" in ENDINGS):
        printFingerprints(fingerprintsHelgrindAllCycles, "Helgrind")
        if(".tsan" in ENDINGS):
            calculateFalsePositivesAndNegatives(fingerprintsTSANAllCycles, fingerprintsHelgrindAllCycles)
            print("-----------------------------------------------------------------------------------")

def parseResultsManualData(results, resultFolder):
    resultList = list()

    #init
    execsNoAtom = [None]*NUMBER_OF_CYCLES
    execsTSAN = [None]*NUMBER_OF_CYCLES
    execsBINTSAN = [None]*NUMBER_OF_CYCLES
    execsHelgrind = [None]*NUMBER_OF_CYCLES

    fingerprintsNoAtom = [None]*NUMBER_OF_CYCLES
    fingerprintsTSAN = [None]*NUMBER_OF_CYCLES
    fingerprintsBINTSAN = [None]*NUMBER_OF_CYCLES
    fingerprintsHelgrind = [None]*NUMBER_OF_CYCLES

    for cycle in range(0,NUMBER_OF_CYCLES):
        fingerprintsNoAtom[cycle] = list()
        fingerprintsTSAN[cycle] = list()
        fingerprintsBINTSAN[cycle] = list()
        fingerprintsHelgrind[cycle] = list()

    #read in logfiles
    for name in results:
        for cycle in range(0, NUMBER_OF_CYCLES):
            for ending in ENDINGS:
                logFilePath = resultFolder+"/"+name+ending+str((cycle+1))
                print(logFilePath)

                if(os.path.isfile(logFilePath)):
                    #logfile already exists, use logfile instead
                    f = open(logFilePath, "rb")
                    err = f.read()
                    f.close()

                    if(err):
                        if(err != ""):
                            err = str(err)
                            #print("err: "+err)
                            if(DATARACE_DETECTION_STRING in err or DATARACE_DETECTION_STRING_HELGRIND in err):

                                #print("err: "+str(result.stderr))
                                if(".hel" in ending):
                                    data = parseOutputHelgrind(err)
                                else:
                                    data = parseOutput(err)

                                if(data is None):
                                    return None
                                
                                file_name = "defaultInput"

                                res = list()
                                res.append((file_name, ending, data))

                                resCleaned = cleanAndFormatResults(res)
                                fingerprints = getCycleResults(resCleaned)

                                if(".tsan" in ending):
                                    fingerprintsTSAN[cycle] = fingerprints
                                elif(".san" in ending):
                                    fingerprintsBINTSAN[cycle] = fingerprints
                                elif(".noAtom" in ending):
                                    fingerprintsNoAtom[cycle] = fingerprints
                                elif(".hel" in ending):
                                    fingerprintsHelgrind[cycle] = fingerprints

        # print results
        print(name+": \n")
        printResults(fingerprintsTSAN, fingerprintsBINTSAN, fingerprintsNoAtom, fingerprintsHelgrind)
        print("----------------------------------------------------")
        print("----------------------------------------------------")
        print("----------------------------------------------------\n\n\n")

def processBenchmark():

    results = [
        "bodytrack",
        "streamcluster",
        "vips",
        "ferret",
        "fluidanimate"
    ]
    resultFolder = "../PARSEC/PARSEC_outputs"

    parseResultsManualData(results, resultFolder)

def processManualData():

    results = [
        "QtNotepad",
        "libQt5Core",
        "axel"
    ]
    resultFolder = "../RealWorld/TestOutputs"

    parseResultsManualData(results, resultFolder)

def processFuzzingData():
    results = FUZZTARGETS

    for (path, arguments) in results:
        programName = path.split("/")[0]

        print("Processing "+programName)
        path = PATH+path

        print("Preparing "+programName)
        prepare(path)
        print("Minimizing "+programName)
        minimize(path, arguments)
        print("Running "+programName)
        execs = runAgainstPrograms(path, arguments)
        print("Results Parsing")
        parseResults(path, arguments, execs)

        print("----------------------------------------------------\n\n\n")


def main():
    processManualData()
    processBenchmark()
    processFuzzingData()

main()