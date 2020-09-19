#include <iostream>
#include <exception>
#include <sys/stat.h>
#include "Utils.hpp"
#include "Nso.hpp"
#include "Disassembler.hpp"
#include <memory>

#define ASM_DIR "out"

void showUsage(std::string error)
{
    std::cout << "ERROR: " << error << std::endl;
    std::cout << "Usage: nsostuff file.nso" << std::endl;
    exit(1);
}

int main(int argc, char** argv)
{
    std::cout << "args:" << std::endl;
    for (size_t i = 0; i < argc; i++)
        std::cout << "[" << i << "] \"" << argv[i] << "\"" << std::endl;

    if (argc != 2)
        showUsage("Invalid argument count");

    if (!Utils::FileExists(argv[1]))
        showUsage("Cannot open file");

    std::unique_ptr<Nso> nso = std::make_unique<Nso>(argv[1]);
    nso->printInfo();
    //nso->saveDecompressed("out");

    mkdir(ASM_DIR, 0777);
    Disassembler::process(nso.get(), ASM_DIR);
    
    return 0;
}
