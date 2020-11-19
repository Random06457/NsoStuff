#pragma once
#include <string>

class NsoFile;

class ElfConvert
{
public:
    static void nso2elf(NsoFile* nso, std::string elfPath);
};
