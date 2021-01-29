#include "Utils.hpp"
#include <fstream>
#include <sys/stat.h>

bool Utils::FileExists(std::string path)
{
    std::ifstream f(path.c_str());
    return f.good();
}

std::vector<u8> Utils::ReadFile(std::string path)
{
    std::ifstream f;
    f.open(path.c_str(), std::ios::in | std::ios::binary | std::ios::ate);

    if (f.is_open())
    {
        auto size = f.tellg();
        f.seekg(0, std::ios::beg);

        std::vector<u8> vec;
        vec.reserve(size);
        vec.resize(size);
        f.read(reinterpret_cast<char *>(vec.data()), size);
        f.close();
        return vec;
    }

    return std::vector<u8>();
}

void Utils::WriteFile(std::string path, void *data, size_t size)
{
    std::ofstream f;
    f.open(path.c_str(), std::ios::out | std::ios::binary);

    if (f.is_open())
    {
        f.write(reinterpret_cast<char *>(data), size);
        f.close();
    }
}

std::string Utils::hexToStr(void* data, size_t size)
{
    u8* ptr = reinterpret_cast<u8*>(data);

    char* str = new char[size*2+1];
    for (size_t i = 0; i < size; i++)
    {
        char nibble  = ptr[i] >> 4;
        str[i*2+0] = nibble + ((nibble < 0xA) ? '0' : 'A' - 0xA);
        nibble = ptr[i] & 0xF;
        str[i*2+1] = nibble + ((nibble < 0xA) ? '0' : 'A' - 0xA);
    }
    str[size*2] = '\0';
    std::string ret(str);
    delete[] str;
    return ret;
}


void Utils::CreateDir(std::string path)
{
    for (size_t i = 0; i < path.size()+1; i++)
        if (i == path.size() || path[i] == '/' || path[i] == '\\')
        {
            s32 res = mkdir(std::string(path, 0, i).c_str(), 0777);
            if (res && errno != EEXIST)
                throw std::runtime_error(("Failed to create dir : " + std::to_string(res)).c_str());
        }
}