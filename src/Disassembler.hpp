#pragma once

#include <functional>
#include <capstone/capstone.h>
#include "Nso/NsoFile.hpp"

class Disassembler
{
private:
    struct SymRef 
    {
        size_t insAddr;
        size_t addr;
    };    

    class Symbol
    {
        
    public:
        Symbol(Elf64_Sym* sym, NsoFile* nso) :
            m_Sym(sym),
            m_Addr(sym->st_value),
            m_Name(nso->rodata<char>(nso->m_Header.dynStr.off + m_Sym->st_name))
        {
        }
        Symbol(size_t addr, NsoFile* nso) :
            m_Sym(nullptr),
            m_Addr(addr)
        {
            char msg[2+8+1] = {0};
            const char* fmt = addr >= nso->m_Header.text.addr && addr < nso->m_Header.text.addr + nso->m_Header.text.size
                ? "L%08lX"
                : "D_%08lX";
            snprintf(msg, sizeof(msg), fmt, addr);
            m_Name = msg;
        }
        
    public:
        Elf64_Sym* m_Sym;
        size_t m_Addr;
        std::string m_Name;
    };

    struct SectionHandler
    {
        std::string m_Name;
        const char* m_Perms;
        bool m_Progbits;
        std::function<void(FILE*, NsoFile::Section*)> m_Handler;

        SectionHandler(const char* name, const char* perms, bool progbits, std::function<void(FILE*, NsoFile::Section*)> handler) :
            m_Name(name),
            m_Perms(perms),
            m_Progbits(progbits),
            m_Handler(handler)
        {
        }
};
    

private:
    Disassembler(NsoFile* nso, std::string asmDir);
    ~Disassembler();

public:
    static void process(NsoFile* nso, std::string asmDir);

private:
    void findSymRefs();
    void generateSymbols();
    void disassemble();
    void writeLd();
    
    void writeTextAsm(FILE* f, size_t start, size_t size);
    void writeDataAsm(FILE* f, size_t start, size_t size, bool bss = false);

    void addTextSectionHandler(const char* name);
    void addDataSectionHandler(const char* name, bool writable, bool bss);
    void addRelaSectionHandler(const char* name);

    Disassembler::Symbol* getSymbol(size_t addr);
    

private:
    NsoFile* m_Nso;
    std::string m_AsmDir;
    csh m_Handle;
    std::vector<Disassembler::SymRef> m_SymRefs;
    std::vector<Disassembler::Symbol> m_Syms;
    std::vector<Disassembler::SectionHandler> m_SectionHandlers;
};