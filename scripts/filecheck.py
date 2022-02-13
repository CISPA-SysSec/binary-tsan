import sys
import re

def patternInLine(line, pattern, definedVariables):
    origPattern = pattern
    pattern = pattern.lstrip().rstrip()
    if "{{" in pattern or "[[" in pattern:
        regexParts = re.findall("({{[^}]+}})", pattern)
        captureParts = re.findall("(\[\[(?:[^]]+]?)*\]\])", pattern)
        pattern = re.escape(pattern)
        for p in regexParts:
            pattern = pattern.replace(re.escape(p), p[2:-2])
        
        variableNames = []
        for p in captureParts:
            captureContent = p[2:-2]
            parts = captureContent.split(":")
            if len(parts) == 1:
                if not captureContent in definedVariables.keys():
                    print("ERROR: unknown variable " + captureContent)
                    exit(1)
                pattern = pattern.replace(re.escape(p), re.escape(definedVariables[captureContent]))
            elif len(parts) == 2:
                pattern = pattern.replace(re.escape(p), "(" + parts[1] + ")")
                variableNames.append(parts[0])
            else:
                print("Pattern error: " + origPattern)
                exit(1)
        matches = re.findall(pattern, line)
        if len(matches) == 0:
            return False
        if isinstance(matches[0], str):
            matches[0] = (matches[0],)
        if len(variableNames) > 0 and len(matches[0]) != len(variableNames):
            print("ERROR: capture in regular regex part: " + pattern)
            exit(1)
        for i in range(len(variableNames)):
            #print("Define variable: " + variableNames[i] + " as " + matches[0][i])
            definedVariables[variableNames[i]] = matches[0][i]
        return True
    else:
        return pattern in line


def checkLines(sourceFile, outputLines):
    checkLines = []
    for line in open(sourceFile, "r").readlines():
        if "// CHECK:" in line or "// CHECK-NOT:" in line or "// CHECK-NEXT:" in line:
            checkLines.append(line.replace("\n", ""))
        elif "// CHECK" in line:
            return (2, "ERROR: unrecognized check: " + line.replace("\n", ""))

    index = 0

    definedVariables = {}

    for check in checkLines:
        if "// CHECK:" in check:
            checkPart = check.replace("// CHECK:", "")
            while True:
                if index >= len(outputLines):
                    return (1, "ERROR: Could not find required pattern: " + checkPart)
                index = index + 1
                if patternInLine(outputLines[index-1], checkPart, definedVariables):
                    break
        
        if "// CHECK-NOT:" in check:
            checkPart = check.replace("// CHECK-NOT:", "")
            for line in outputLines:
                if patternInLine(line, checkPart, definedVariables):
                    return (1, "ERROR: Line matches check-not: " + line.replace("\n", ""))
        
        if "// CHECK-NEXT:" in check:
            checkPart = check.replace("// CHECK-NEXT:", "")
            if not patternInLine(outputLines[index], checkPart, definedVariables):
                return (1, "ERROR: Could not find required pattern in next line: " + checkPart)
            index = index + 1
    return (0, "")

def checkFile(sourceFile, outputFile):
    outputLines = open(outputFile, "r").readlines()
    return checkLines(sourceFile, outputLines)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 " + sys.argv[0] + " source-file program-output")
        quit()

    checkFile(sys.argv[1], sys.argv[2])
