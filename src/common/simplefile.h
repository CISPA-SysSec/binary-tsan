#ifndef SIMPLEFILE_H
#define SIMPLEFILE_H

#include <google/protobuf/message.h>
#include <string>
#include <fstream>

// as the read and write happens on the same computer, bit-width and endian-ness stays the same
inline bool writeProtobufToFile(const google::protobuf::Message &message, const std::string &filename)
{
    std::ofstream file;
    file.open(filename);
    if (!file) {
        return false;
    }
    std::vector<char> data(message.ByteSize());
    if (!message.IsInitialized() || !message.SerializeToArray(data.data(), data.size())) {
        return false;
    }
    file.write(data.data(), data.size());
    return true;
}


inline bool readProtobufFromFile(google::protobuf::Message &message, const std::string &filename)
{
    std::ifstream file;
    file.open(filename, std::ifstream::ate | std::ifstream::binary);
    if (!file) {
        return false;
    }
    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> data(size, 0);
    file.read(data.data(), size);
    if (!message.ParseFromArray(data.data(), data.size())) {
        return false;
    }
    return true;
}

#endif // SIMPLEFILE_H
