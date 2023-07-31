#!/usr/bin/python3

import os
import csv
import pandas as pd

debugPrint = False
outputCSV = True

DATAPATH = "./data"
OUTPUTPATH = "./generated"


targetsParsec = ["dedup", "ferret", "blackscholes", "streamcluster", "fluidanimate", "swaptions", "vips", "bodytrack", "raytrace", "canneal", "facesim", "x264", "freqmine"]
targetsSpec = ["505.mcf_r", "531.deepsjeng_r", "541.leela_r", "548.exchange2_r", "557.xz_r", "523.cpuxalan_r", "525.x264_r"] # "520.omnetpp_r",
targetsReal = ["lrzip", "ffmpeg", "sqlite3", "rar", "x265", "reaper", "plzip", "QtNotepad", "pigz", "pbz2", "unrar", "xz", "axel", "libQt5Core", "libSwell"]
# alternatives:  "pxz", "pixz", "x264","memcached", "PaRMAT", "x264", "b1manager", "libdbus-1"
#old rw targets: , "masterpdfeditor5", "XnView", "okular", "dalted", "vuescan", "monkey", "libQt5Core", "libgomp"


versionInfo =	{
  "lrzip": "'0.651'",
  "ffmpeg": "N-110171-g2244722f1f",
  "sqlite3": "3.42.0",
  "rar": "6.22 beta 1",
  "x265": "3.4.1",
  "reaper": "6.80",
  "plzip": "1.9",
  "QtNotepad": "1.0",
  "pigz": "2.7",
  "pbz2": "1.1.13",
  "unrar": "6.22 beta 1",
  "xz": "5.4.3",
  "axel": "2.17.11",
  "libQt5Core": "5.15.2",
  "libSwell": "1.0",
  "libdbus-1": "1.3",
  "PARSEC": "3",
  "SPEC": "1.1.0",
}


#languages
ListCPrograms = ["505.mcf r", "557.xz r", "blackscholes", "dedup", "ferret", "x264", "lrzip", "ffmpeg", "sqlite3", "pigz", "xz", "525.x264_r", "axel", "libdbus-1"]
ListFortranPrograms = ["548.exchange2_r"]
ListUnknownLangPrograms = ["reaper"]
#closedSource Programs 

ListClosedSourcePrograms = ["b1manager", "rar", "reaper"]


def findLine(needle, line):
    if needle in line:
        return line.index(needle)+len(needle)
    else:
        return 0

def getValue(needle, line):
    pos = findLine(needle, line)
    if(pos):
        val = line[pos:].strip()
        return [needle, val]

def getTarget(content):
    content = "\n".join(content)
    if(not "tsan_temp." in content):
        print("WARNING: 'tsan_temp.' not find in logfile, might indicate broken logfile!")
        return -1
    pos = findLine("tsan_temp.", content)
    target = str(content[pos:].split(".")[0])

    return target


def parse_content(dirpath, content):
    result = list()

    target = getTarget(content)
    if(target == -1):
        print("ERROR: target not detected for dirpath: "+str(dirpath))

    #process target names
    target = target.replace("_base", "")

    if(target == "rtview"):
        target = "raytrace"
    elif(target == "mcf_r"):
        target = "505."+target
    elif(target == "deepsjeng_r"):
        target = "531."+target
    elif(target == "leela_r"):
        target = "541."+target
    elif(target == "exchange2_r"):
        target = "548."+target
    elif(target == "xz_r"):
        target = "557."+target
    elif(target == "omnetpp_r"):
        target = "520."+target
    elif(target == "cpuxalan_r"):
        target = "523."+target
    elif(target == "x264_r"):
        target = "525."+target

    
    result.append(["Target:", target])

    #add benchmark info
    if(target in targetsParsec):
        result.append(["Benchmark:", "PARSEC"])
    elif(target in targetsSpec):
        result.append(["Benchmark:", "SPEC"])
    elif(target in targetsReal):
        result.append(["Benchmark:", "_REAL"])
    else:
        result.append(["Benchmark:", "None"])

    exitcode = getValue("#ATTRIBUTE step_exitcode=", "\n".join(content))[1]
    result.append(["Exitcode:", exitcode])
    if(exitcode != "0"):
        print("WARNING: log parsed, where tsan exit code is "+str(exitcode)+" for target: "+str(target)+"\n")

    for line in content:
        result.append(getValue("Total instructions:", line))
        result.append(getValue("Analyzed Functions:", line))
        result.append(getValue("Entry/Exit instrumented:", line))
        result.append(getValue("Register analyzed:", line))
        result.append(getValue("Analyzed Instructions:", line))
        result.append(getValue("New Instrumentation Instructions:", line))
        result.append(getValue("Memory Access:", line))
        result.append(getValue("Function Entry/Exit:", line))
        result.append(getValue("Exception Handling:", line))
        result.append(getValue("Wrapper Functions:", line))
        result.append(getValue("Instrumented Instructions:", line))
        result.append(getValue("Not instrumented:", line))
        result.append(getValue("Stack Canaries:", line))
        result.append(getValue("Stack Local Variables:", line))
        result.append(getValue("Constant Memory Read:", line))
        result.append(getValue("Stack Memory:", line))
        #result.append(getValue("Inferred Atomics:", line))
        result.append(getValue("Lock Prefix and Xchg(not inferred):", line))
        result.append(getValue("Pointer Inference:", line))
        result.append(getValue("Static Variable Guards:", line))
        result.append(getValue("Spin Locks:", line))

    #remove Nones
    result_cleaned = [i for i in result if i is not None]

    return result_cleaned



def parse_dir(dirpath):
    #print(dirpath)
    logpath = dirpath+"/logs"
    tsanlog = logpath+"/tsan.log"
    if(not os.path.exists(tsanlog)):
        print("ERROR: tsan.log not found for logdir: "+dirpath+"\n")
        return 1
    logfile = open(tsanlog, "r")
    
    logcontent = logfile.readlines()
    result = parse_content(dirpath, logcontent)
    if(debugPrint):
        for res in result:
            print(res[0]+" "+res[1])
    
    return result

def prepareData(data):
    dfs = list()
    for entry in data:
        df = pd.DataFrame(entry, columns = ['attribute', ''])
        df = df.set_index("attribute").T # use attribute column as new header
        #df = df.reset_index(drop=True)
        dfs.append(df)
    
    alldf = pd.concat(dfs)

    #rename headers
    alldf.rename(columns={'New Instrumentation Instructions:': 'Added I Total:'}, inplace=True)
    alldf.rename(columns={'Memory Access:': 'Added I MemAccess:'}, inplace=True)
    alldf.rename(columns={'Function Entry/Exit:': 'Added I Funct Entry/Exit:'}, inplace=True)

    if('Lock Prefix and Xchg(not inferred):' in alldf):
        alldf.rename(columns={'Lock Prefix and Xchg(not inferred):': 'Atomics:'}, inplace=True)
    else:
        alldf['Atomics:'] = 'N/A'

    alldf.rename(columns={'Instrumented Instructions:': 'Instrumented MemAccesses:'}, inplace=True)

    alldf['Detected MemAccesses:'] = alldf['Instrumented MemAccesses:'].astype(int) + alldf['Not instrumented:'].astype(int)


    #alldf = alldf.set_index("Target:").T
    alldf = alldf.sort_values(by=['Benchmark:', 'Target:'], ascending=[False, True])
    print(alldf)

    
    return alldf

def generateFullData(data):
    filePath = OUTPUTPATH+"/full_data.csv"
    data.to_csv(filePath, sep=';', index=False)

def generateDataset(data):
    filePath = OUTPUTPATH+"/dataset.csv"

    data = data[data["Benchmark:"] != "None"]

    data.to_csv(filePath, sep=';', index=False)

    return data

def generateRWDatasset(data):
    filePath = OUTPUTPATH+"/dataset_RW.csv"

    data = data[data["Benchmark:"] == "_REAL"]

    data.to_csv(filePath, sep=';', index=False)

    return data

def generateBenchmarkDatasset(data):
    filePath = OUTPUTPATH+"/dataset_Benchmark.csv"

    dataSPEC = data[data["Benchmark:"] == "SPEC"]
    dataPARSEC = data[data["Benchmark:"] == "PARSEC"]

    dataBenchmark = pd.concat([dataSPEC, dataPARSEC])

    dataBenchmark.to_csv(filePath, sep=';', index=False)

    return dataBenchmark


def generateGeneralInfo(data):
    filePath = OUTPUTPATH+"/table_dataset_Info.csv"

    selectedData = pd.DataFrame(data[["Target:", "Benchmark:", "Total instructions:", "Analyzed Functions:", "Detected MemAccesses:"]])
    selectedData['Lang'] = 'C++'
    selectedData['OSS'] = 'True'
    selectedData['Version'] = '-'

    for index, row in selectedData.iterrows():
        #print(row)
        progName = row['Target:']
        benchmark = row['Benchmark:']
        #set languages other than C++
        if(progName in ListCPrograms):
            selectedData.loc[selectedData['Target:'] == progName, "Lang"] = "C"
        elif(progName in ListFortranPrograms):
            selectedData.loc[selectedData['Target:'] == progName, "Lang"] = "Fortran"
        elif(progName in ListUnknownLangPrograms):
            selectedData.loc[selectedData['Target:'] == progName, "Lang"] = "Unknown"
        #set closed source programs
        if(progName in ListClosedSourcePrograms):
            selectedData.loc[selectedData['Target:'] == progName, "OSS"] = "False"

        #get version info
        if(benchmark in versionInfo):
            selectedData.loc[selectedData['Target:'] == progName, "Version"] = versionInfo[benchmark]
        elif(progName in versionInfo):
            selectedData.loc[selectedData['Target:'] == progName, "Version"] = versionInfo[progName]

    selectedData.to_csv(filePath, sep=';', index=False)

def generateOptimizationImpact(data):
    filePath = OUTPUTPATH+"/table_optimizations.csv"

    selectedData = pd.DataFrame(data[["Target:", "Detected MemAccesses:", "Stack Canaries:", "Stack Local Variables:", "Constant Memory Read:"]])
    selectedData['Total'] = "-1"
    selectedData['TotalSorting'] = "-1"

    selectedData.index = [x for x in range(1, len(selectedData.values)+1)]

    for index, row in selectedData.iterrows():
        progName = row['Target:']
        instr = int(row['Detected MemAccesses:'])
        sc = int(row['Stack Canaries:'])
        slm = int(row['Stack Local Variables:'])
        cmr = int(row['Constant Memory Read:'])
        total = sc+slm+cmr
        totalPercentage = round((total/instr)*100, 2)
        selectedData.loc[selectedData['Target:'] == progName, "Total"] = str(total)+" ("+str(totalPercentage)+"%)"
        selectedData.loc[selectedData['Target:'] == progName, "TotalSorting"] = totalPercentage

        if((total == 0)):
            selectedData.drop(index, inplace=True)

    selectedData.sort_values(by=['TotalSorting'], ascending=False, inplace=True)
    selectedData.drop(columns=['TotalSorting'], inplace=True)

    selectedData.to_csv(filePath, sep=';', index=False)

def generateAtomOpsHeuristicsImpact(data):
    filePath = OUTPUTPATH+"/table_atomOpsHeuristics.csv"

    selectedData = pd.DataFrame(data[["Target:", "Atomics:", "Pointer Inference:", "Static Variable Guards:", "Spin Locks:"]])
    selectedData['Total'] = "-1"

    selectedData.index = [x for x in range(1, len(selectedData.values)+1)]

    for index, row in selectedData.iterrows():
        progName = row['Target:']
        if(str(row["Atomics:"]).isdigit()):
            atomics = int(row["Atomics:"])
        else:
            atomics = 0
        ptinf = int(row["Pointer Inference:"])
        svguard = int(row["Static Variable Guards:"])
        spinlocks = int(row["Spin Locks:"])
        total = atomics+ptinf+svguard+spinlocks
        selectedData.loc[selectedData['Target:'] == progName, "Total"] = total
        #print(progName)
        #print(index)
        if((total == 0)):
            selectedData.drop(index, inplace=True)


    selectedData = selectedData.sort_values(by=['Total'], ascending=False)
    
    selectedData.to_csv(filePath, sep=';', index=False)



def generateResults(data):
    allData = prepareData(data)

    generateFullData(allData)
    #data set and split up in rw and benchmark
    dataset = generateDataset(allData)
    rw = generateRWDatasset(dataset)
    benchmark = generateBenchmarkDatasset(dataset)

    #produce tables for paper
    generateGeneralInfo(dataset)
    generateOptimizationImpact(rw)
    generateAtomOpsHeuristicsImpact(rw)

def main():
    path=DATAPATH

    data = list()

    for dir in os.listdir(path):
        dirpath = path+"/"+dir
        if(os.path.isdir(dirpath)):
            targetData = parse_dir(dirpath)
            data.append(targetData)
            if(debugPrint):
                print()#newline
            
    #print(os.listdir(path))
    if(outputCSV):
        generateResults(data)


    

main()