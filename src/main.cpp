#include <iostream>
#include <exception>
#include <sys/stat.h>
#include "Utils.hpp"
#include "Nso.hpp"
#include "Disassembler.hpp"
#include <memory>

#define ASM_DIR "out"

#define ARG_PROG    0
#define ARG_INPUT   1
#define ARG_MODE    2
#define ARG_OUTPUT  3

void showUsage(std::string error, char** argv)
{
    std::cout << "ERROR: " << error << std::endl;
    std::cout << "Usage: " << argv[ARG_PROG] << " <input file> <mode> (<output>)" << std::endl;
    exit(1);
}

int main(int argc, char** argv)
{
    std::cout << "args:" << std::endl;
    for (size_t i = 0; i < argc; i++)
        std::cout << "\t[" << i << "] \"" << argv[i] << "\"" << std::endl;

    if (argc <= 2)
        showUsage("Too few arguments", argv);

    if (!Utils::FileExists(argv[ARG_INPUT]))
        showUsage("Input file does not exist", argv);
    
    std::unique_ptr<Nso> nso = std::make_unique<Nso>(argv[ARG_INPUT]);

    if (argc == 3)
    {
        if (!strcmp("info", argv[ARG_MODE]))
            nso->printInfo();
        else showUsage(std::string("Invalid mode : ") + argv[ARG_MODE], argv);
    }

    if (argc == 4)
    {
        if (!strcmp(argv[ARG_MODE], "decompress"))
        {
            nso->saveDecompressed(argv[ARG_OUTPUT]);
        }
        else if (!strcmp(argv[ARG_MODE], "disassemble"))
        {
            mkdir(ASM_DIR, 0777);
            Disassembler::process(nso.get(), argv[ARG_OUTPUT]);
        }
        else showUsage(std::string("Invalid mode : ") + argv[ARG_MODE], argv);
    }
    
    return 0;
}
