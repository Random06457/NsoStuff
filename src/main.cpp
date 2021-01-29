#include <iostream>
#include <exception>
#include <memory>
#include "Utils.hpp"
#include "Nso/NsoFile.hpp"
#include "Disassembler.hpp"

void showUsage(std::string error, char** argv);

struct ArgReader
{
    char** m_Argv;
    size_t m_Argc;
    size_t m_ArgIdx;

    ArgReader(int argc, char** argv)
    {
        m_Argc = argc;
        m_Argv = argv;
        m_ArgIdx = 0;
    }
    inline bool canRead() { return m_ArgIdx < m_Argc; }
    inline const char* read() { return canRead() ? m_Argv[m_ArgIdx++] : nullptr; }
    const char* readPath() {
        const char* file = read();
        if (!file || !Utils::FileExists(file))
            showUsage("Input file does no exist", m_Argv);
        return file;
    };
};

struct ModeHandler
{
    const char* name;
    std::vector<std::string> args;
    std::function<void(ArgReader*)> callback;
};

std::vector<ModeHandler> g_Handlers =
{
    { "elf2nso", { "input.elf", "output.nso" },
        [] (ArgReader* reader) {
            auto nso = NsoFile::fromELF(reader->readPath());
            nso.writeCompressed(reader->read());
        }
    },
    { "nso2elf", { "input.nso", "output.elf" },
        [] (ArgReader* reader) {
            auto nso = NsoFile::fromNSO(reader->readPath());
            nso.writeELF(reader->read());
        }
    },
    { "info", { "input.nso" },
        [] (ArgReader* reader) {
            auto nso = NsoFile::fromNSO(reader->readPath());
            nso.printInfo();
    }, },

    { "decompress", { "input.nso", "output.nso" },
        [] (ArgReader* reader) {
            auto nso = NsoFile::fromNSO(reader->readPath());
            nso.writeDecompressed(reader->read());
    }, },

    { "compress", { "input.nso", "output.nso" },
        [] (ArgReader* reader) {
            auto nso = NsoFile::fromNSO(reader->readPath());
            nso.writeCompressed(reader->read());
    }, },

    { "disassemble", { "input.nso", "output folder" },
        [] (ArgReader* reader) {
            auto nso = NsoFile::fromNSO(reader->readPath());
            const char* folder = reader->read();
            
            Utils::CreateDir(folder);
            Disassembler::process(&nso, folder);
    }, },
};

void showUsage(std::string error, char** argv)
{
    std::cout << "ERROR: " << error << std::endl;
    std::cout << "Usage: " << argv[0] << " <mode> ..." << std::endl;
    for (auto handler : g_Handlers)
    {
        std::cout << "\t- " << handler.name;
        for (auto arg : handler.args)
            std::cout << " <" << arg << ">";
        std::cout << std::endl;
    }
    
    exit(1);
}

int main(int argc, char** argv)
{
    std::cout << "args:" << std::endl;
    for (size_t i = 0; i < argc; i++)
        std::cout << "\t[" << i << "] \"" << argv[i] << "\"" << std::endl;
    std::cout << std::endl;

    ArgReader reader(argc, argv);

    reader.read(); // program name
    if (!reader.canRead())
        showUsage("Too few arguments", argv);

    const char* mode = reader.read();
    bool found = false;
    for (auto handler : g_Handlers)
    {
        if (!strcmp(handler.name, mode))
        {
            if (argc != 2 + handler.args.size())
                showUsage("Invalid argument count", argv);
            
            handler.callback(&reader);
            found = true;
            break;
        }
    }

    if (!found)
        showUsage("Invalid mode", argv);
    
    return 0;
}
