#pragma once
#include <string>
#include <vector>
#include "Types.h"

#define STR_TO_U32(a, b, c, d) ((((d) & 0xFF) << 24) | (((c) & 0xFF) << 16) | (((b) & 0xFF) << 8) | ((a) & 0xFF)) 

template<int CONST>
struct FileMagic
{
    union
    {
        u32 value;
        char name[4];
    };

    bool isValid() { return value == CONST; }
    std::string toString()
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "\"%c%c%c%c\" (0x%08X) : %s", name[0], name[1], name[2], name[3], value, isValid() ? "VALID" : "INVALID");
        return std::string(msg);
    }
};

class Utils
{
public:
    static bool FileExists(std::string path);
    static std::vector<u8> ReadFile(std::string path);
    static void WriteFile(std::string path, void* data, size_t size);
    static std::string hexToStr(void* data, size_t size);
};