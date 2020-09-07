#pragma once

#include "Nso.hpp"
#include <capstone/capstone.h>

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
        Symbol(Elf64_Sym* sym, Nso* nso) :
            m_Sym(sym),
            m_Addr(sym->st_value),
            m_Name(nso->rodata<char>(nso->m_Header.dynStr.off + m_Sym->st_name))
        {
        }
        Symbol(size_t addr, Nso* nso) :
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
    

private:
    Disassembler(Nso* nso, std::string asmDir);
    ~Disassembler();

public:
    static void process(Nso* nso, std::string asmDir);

private:
    void findSymRefs();
    void generateSymbols();
    void disassemble();
    
    void writeTextAsm(FILE* file, size_t size, const char* sectionName);
    void writeDataAsm();
    void writeRodataAsm();
    void writeBssAsm();

    Disassembler::Symbol* getSymbol(size_t addr);
    

private:
    FILE* m_TextFile;
    FILE* m_RodataFile;
    FILE* m_DataFile;
    FILE* m_BssFile;
    Nso* m_Nso;
    csh m_Handle;
    size_t m_CurAddr;
    std::vector<Disassembler::SymRef> m_SymRefs;
    std::vector<Disassembler::Symbol> m_Syms;
};