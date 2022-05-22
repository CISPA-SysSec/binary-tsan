#include "options.h"

#include <algorithm>
#include <fstream>
#include <iomanip>

#include "stringhelper.h"

using namespace IRDB_SDK;

class OptionsManager
{
private:
    class Option {
    public:
        Option(const std::string &name, const std::string &description, bool hasValue) :
            name(name),
            description(description),
            hasValue(hasValue)
        { }
        virtual bool applyOption(const std::string &value) = 0;
        virtual std::string getFullName() { return "--" + name; }

        std::string name;
        std::string description;
        bool hasValue;
    };

    class FlagOption : public Option {
    public:
        FlagOption(const std::string &name, bool *outValue, bool setTo, const std::string &description) :
            Option(name, description, false),
            outValue(outValue),
            setTo(setTo)
        { }
        bool applyOption(const std::string &) override {
            *outValue = setTo;
            return true;
        }
    private:
        bool *outValue;
        bool setTo;
    };

    class StringOption : public Option {
    public:
        StringOption(const std::string &name, const std::string &valueName, std::string *outValue, const std::string &description) :
            Option(name, description, true),
            outValue(outValue),
            valueName(valueName)
        { }
        bool applyOption(const std::string &value) override {
            *outValue = value;
            return true;
        }
        std::string getFullName() override {
            return "--" + name + "=<" + valueName + ">";
        }
    private:
        std::string *outValue;
        std::string valueName;
    };

    class EnumOption : public Option {
    public:
        EnumOption(const std::string &name, int *outValue, const std::vector<std::pair<std::string, int>> &options, const std::string &defaultName, const std::string &description) :
            Option(name, description, true),
            outValue(outValue),
            options(options),
            defaultName(defaultName)
        { }
        bool applyOption(const std::string &value) override {
            for (const auto &[name, val] : options) {
                if (name == value) {
                    *outValue = val;
                    return true;
                }
            }
            std::cout <<"ERROR: "<<value<<" is not a valid value for option "<<name<<std::endl;
            return false;
        }
        std::string getFullName() override {
            std::string result =  "--" + name + "=(";
            for (std::size_t i = 0;i<options.size();i++) {
                result += options[i].first;
                if (i+1 < options.size()) {
                    result += "|";
                }
            }
            result += ")";
            return result;
        }
    private:
        int *outValue;
        std::vector<std::pair<std::string, int>> options;
        std::string defaultName;
    };

public:
    void addFlagOption(const std::string &name, bool *value, bool setValueTo, const std::string &description) {
        options.push_back(std::make_unique<FlagOption>(name, value, setValueTo, description));
    }
    void addStringOption(const std::string &name, const std::string &valueName, std::string *value, const std::string &description) {
        options.push_back(std::make_unique<StringOption>(name, valueName, value, description));
    }
    // WARNING: the default value is not actually set, the defaultName is just for the help message
    void addEnumOption(const std::string &name, int *value, const std::vector<std::pair<std::string, int>> &opt, const std::string &defaultName, const std::string &description) {
        options.push_back(std::make_unique<EnumOption>(name, value, opt, defaultName, description));
    }

    bool parseOptions(const std::vector<std::string> &options) const;
    void printHelp() const;

private:
    std::vector<std::unique_ptr<Option>> options;
};

bool OptionsManager::parseOptions(const std::vector<std::string> &optionString) const
{
    for (const std::string &optStr : optionString) {
        if (!startsWith(optStr, "--")) {
            // TODO: put the error message to a better place
            std::cout <<"ERROR: options must start with a --"<<std::endl;
            return false;
        }
        const std::string withoutStart(optStr.begin() + 2, optStr.end());
        const std::vector<std::string> parts = split(withoutStart, '=');
        if (parts.size() > 2) {
            std::cout <<"ERROR: option string must include at most one '=' character"<<std::endl;
            return false;
        }
        const std::string optionName = parts[0];
        const std::string optionValue = parts.size() > 1 ? parts[1] : "";

        const auto optionIt = std::find_if(options.begin(), options.end(), [&optionName](const auto &opt) {
            return opt->name == optionName;
        });
        if (optionIt == options.end()) {
            std::cout <<"ERROR: unrecognized option: "<<optionName<<std::endl;
            return false;
        }
        const auto &option = *optionIt;
        if (!option->hasValue && optionValue.size() > 0) {
            std::cout <<"ERROR: value provided for an option that does not take one: "<<optionName<<std::endl;
            return false;
        }
        if (option->hasValue && optionValue.size() == 0) {
            std::cout <<"ERROR: missing value for option: "<<optionName<<std::endl;
            return false;
        }
        if (!option->applyOption(optionValue)) {
            return false;
        }
    }
    return true;
}

void OptionsManager::printHelp() const
{
    std::cout <<"Available options:"<<std::endl<<std::endl;

    std::size_t maxOptionNameLen = 0;
    for (const auto &opt : options) {
        maxOptionNameLen = std::max(maxOptionNameLen, opt->getFullName().size());
    }
    for (const auto &opt : options) {
        std::cout <<setw(maxOptionNameLen + 3)<<std::left<<opt->getFullName();
        std::string description = opt->description;
        bool isFirst = true;
        const int SHOW_LENGTH = 100;
        while (description.size() > 0) {
            const std::string part = description.size() > SHOW_LENGTH ? std::string(description.begin(), description.begin() + SHOW_LENGTH) : description;
            if (isFirst) {
                isFirst = false;
                std::cout <<part<<std::endl;
            } else {
                std::cout <<setw(maxOptionNameLen + 3)<<std::right<<" "<<part<<std::endl;
            }

            if (description.size() > SHOW_LENGTH) {
                description.erase(description.begin(), description.begin() + SHOW_LENGTH);
            } else {
                break;
            }
        }
    }
    std::cout <<std::endl;

    std::cout <<"Examples: "<<std::endl;
    std::cout <<"./thread-sanitizer.sh /usr/bin/ls ls-mod --register-analysis=stars --dry-run"<<std::endl;
}

struct OptionsPrivate
{
    std::string dumpFunctionNamesTo;
    std::string instrumentOnlyFrom;
    std::string annotationsFile;
    std::string dumpInstrumentedInstructions;
};

static OptionsManager registerTsanOptions(Options &options, OptionsPrivate &additionalOptions)
{
    OptionsManager result;
    result.addFlagOption("dry-run", &options.dryRun, true, "Runs the same as an ordinary run, but does not add any instructions.");
    result.addFlagOption("atomics-only", &options.atomicsOnly, true, "Only instrument atomic instructions or inferred atomic instructions.");
    result.addFlagOption("no-entry-exit", &options.instrumentFunctionEntryExit, false, "Do not create function entry/exit instrumentation, including exceptions. Tsan stack traces will only have one entry.");
    result.addFlagOption("no-add-tsan-calls", &options.addTsanCalls, false, "Do not create function calls to the tsan runtime. Instructions for saving and restoring registers will be kept. For benchmarking purposes only.");
    result.addFlagOption("no-add-libtsan-dependency", &options.addLibTsanDependency, false, "Do not add dependency to libtsan.so. This can be used when instrumenting a library to be used with an executable that is statically linked to a thread sanitizer runtime.");
    result.addFlagOption("no-instrument-atomics", &options.noInstrumentAtomics, true, "Do not instrument atomic instructions. For testing purposes only.");
    result.addFlagOption("use-system-libtsan", &options.useCustomLibTsan, false, "Use the sustem libtsan.so instead of the custom built one. This requires saving the xmm registers, which can significantly slow down the instrumented binary.");
    result.addFlagOption("use-wrapper-functions", &options.useWrapperFunctions, true, "Use wrapper functions for calling the thread sanitizer runtime. This slows down the instrumented binary, but creates far fewer instructions, making instrumenting larger binaries possible.");
    result.addFlagOption("no-instrument-stack", &options.instrumentStackAccess, false, "If used, do not instrument instructions that access the stack of the current function.");
    result.addFlagOption("use-memory-profiler", &options.useMemoryProfiler, true, "Use the memory profiler instead of the thread sanitizer run-time library. It prints the output at program termination.");

    const std::vector<std::pair<std::string, int>> registerOptions = {
        {"none", (int)DeadRegisterAnalysisType::NONE},
        {"stars", (int)DeadRegisterAnalysisType::STARS},
        {"custom", (int)DeadRegisterAnalysisType::CUSTOM}
    };
    result.addEnumOption("register-analysis", (int*)&options.deadRegisterAnalysisType, registerOptions, "custom", "The dead register analysis used for eliminating register stores and enabling some transformations. Custom is the default. Stars is the zipr provided analysis.");

    result.addStringOption("dump-function-names-to", "filename", &additionalOptions.dumpFunctionNamesTo, "Dump all functionnames that are encountered into the file specified by <filename>. The names are mangled.");
    result.addStringOption("dump-instrumented-instructions", "filename", &additionalOptions.dumpInstrumentedInstructions, "Write the virtual offsets of all instrumented instructions into the file specified by <filename>.");
    result.addStringOption("instrument-only-functions", "filename", &additionalOptions.instrumentOnlyFrom, "Read the file specified by <filename> and only instrument functions with names in the file. The names must be mangled and in the same format as when they are dumped by --dump-function-names-to. One name per line.");
    result.addStringOption("annotations", "filename", &additionalOptions.annotationsFile, "Load the content from <filename> as annotations for additional information during the instrumentation.");

    return result;
}

void Options::printOptionsHelp()
{
    Options temp;
    OptionsPrivate tempPrivate;
    OptionsManager manager = registerTsanOptions(temp, tempPrivate);
    manager.printHelp();

    // TODO: paths should be absolute
}

std::optional<Options> Options::parseAndProcess(IRDB_SDK::FileIR_t *ir, const std::vector<std::string> &options)
{
    Options result;
    OptionsPrivate tempPrivate;
    const OptionsManager manager = registerTsanOptions(result, tempPrivate);
    if (!manager.parseOptions(options)) {
        return {};
    }
    result.saveXmmRegisters = !result.useCustomLibTsan;

    if (tempPrivate.dumpFunctionNamesTo.size() > 0) {
        std::cout <<"Dumping function names to: "<<tempPrivate.dumpFunctionNamesTo<<std::endl;
        std::ofstream file(tempPrivate.dumpFunctionNamesTo, std::ios_base::binary);
        if (!file) {
            std::cout <<"ERROR: Could not open file!"<<std::endl;
            return {};
        }
        for (Function_t *function : ir->getFunctions()) {
            file <<function->getName()<<std::endl;
        }
    }
    if (tempPrivate.instrumentOnlyFrom.size() > 0) {
        std::cout <<"Reading filenames from: "<<tempPrivate.instrumentOnlyFrom<<std::endl;
        ifstream file(tempPrivate.instrumentOnlyFrom);
        if (!file) {
            std::cout <<"ERROR: Could not open file!"<<std::endl;
            return {};
        }
        std::string line;
        while(getline(file, line)) {
            result.instrumentOnlyFunctions.insert(line);
        }
        std::cout <<"Loaded "<<result.instrumentOnlyFunctions.size()<<" functions to instrument"<<std::endl;
    }
    if (tempPrivate.annotationsFile.size() > 0) {
        const bool res = result.annotations.parseFromFile(ir, tempPrivate.annotationsFile);
        if (!res) {
            std::cout <<"ERROR: Could not load annotations!"<<std::endl;
            return {};
        }
    }
    if (tempPrivate.dumpInstrumentedInstructions.size() > 0) {
        std::cout <<"try open: "<<tempPrivate.dumpInstrumentedInstructions<<std::endl;
        result.dumpInstrumentedInstructions = std::make_shared<std::ofstream>(tempPrivate.dumpInstrumentedInstructions, std::ios_base::binary);
        if (!result.dumpInstrumentedInstructions->is_open()) {
            std::cout <<"ERROR: Could not open file!"<<std::endl;
            return {};
        }
    }
    if (result.useMemoryProfiler) {
        result.deadRegisterAnalysisType = DeadRegisterAnalysisType::NONE;
        result.instrumentFunctionEntryExit = false;
        result.saveXmmRegisters = true;
        result.noInstrumentAtomics = true;
        result.useWrapperFunctions = true;
    }

    return result;
}
