#ifndef SIMPLEFILE_H
#define SIMPLEFILE_H

#include <vector>
#include <string>
#include <fstream>

// as the read and write happens on the same computer, bit-width and endian-ness stays the same
template<typename T>
void writeSimpleDataToFile(const std::vector<T> &data, const std::string &filename)
{
    std::ofstream file;
    file.open(filename);
    if (!file) {
        return;
    }
    const std::size_t length = data.size();
    file.write((char*)&length, sizeof(length));
    file.write((char*)data.data(), data.size() * sizeof(T));
}

template<typename T>
std::vector<T> readSimpleDataFromFile(const std::string &filename)
{
    std::ifstream file;
    file.open(filename);
    if (!file) {
        return {};
    }
    std::size_t length = 0;
    file.read((char*)&length, sizeof(length));

    std::vector<T> result(length);
    file.read((char*)result.data(), length * sizeof(T));
    return result;
}

#endif // SIMPLEFILE_H
