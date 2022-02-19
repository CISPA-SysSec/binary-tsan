#ifndef STRINGHELPER_H
#define STRINGHELPER_H

#include <vector>
#include <string>

inline std::vector<std::string> split(const std::string &txt, char ch)
{
    size_t pos = txt.find( ch );
    size_t initialPos = 0;

    std::vector<std::string> result;
    while( pos != std::string::npos ) {
        result.push_back( txt.substr( initialPos, pos - initialPos ) );
        initialPos = pos + 1;
        pos = txt.find( ch, initialPos );
    }
    result.push_back( txt.substr( initialPos, std::min( pos, txt.size() ) - initialPos + 1 ) );
    return result;
}

inline bool contains(const std::string &str, const std::string &search)
{
    return str.find(search) != std::string::npos;
}

#endif // STRINGHELPER_H
