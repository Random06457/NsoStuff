#include "Disassembler.hpp"
#include <exception>
#include <stdexcept>
#include <cstring>
#include <algorithm>

#define CODE_BUF_SIZE    0x1000
#define ELEMENT_EXISTS(vec, element) (std::find(vec.begin(), vec.end(), element) != vec.end())

Disassembler::Disassembler(Nso* nso, std::string asmDir) :
    m_TextFile(nullptr),
    m_RodataFile(nullptr),
    m_DataFile(nullptr),
    m_BssFile(nullptr),
    m_Nso(nso),
    m_Handle(0),
    m_CurAddr(m_Nso->m_Header.text.addr),
    m_SymRefs(),
    m_Syms()
{

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &m_Handle) != CS_ERR_OK)
        throw std::runtime_error("cs_open failed");

    cs_option(m_Handle, CS_OPT_DETAIL, CS_OPT_ON);

    /*
    m_TextFile = fopen((asmDir + "/main.text.s").c_str(), "wb");
    m_RodataFile = fopen((asmDir + "/main.rodata.s").c_str(), "wb");
    m_DataFile = fopen((asmDir + "/main.data.s").c_str(), "wb");
    m_BssFile = fopen((asmDir + "/main.bss.s").c_str(), "wb");
    */
    m_TextFile = fopen((asmDir + "/rtld/main.s").c_str(), "wb");
}

Disassembler::~Disassembler()
{
    cs_close(&m_Handle);
    fclose(m_TextFile);
    /*
    fclose(m_RodataFile);
    fclose(m_DataFile);
    fclose(m_BssFile);
    */
}

void Disassembler::process(Nso* nso, std::string asmDir)
{
    Disassembler* dis = new Disassembler(nso, asmDir);

    printf("Finding Symbol References...\n");
    dis->findSymRefs();

    printf("Generating Symbol List...\n");
    dis->generateSymbols();

    //printf("Finding ELF sections...\n");
    //dis->findElfSections();

    printf("Disassembling...\n");
    //dis->disassemble();

    printf("Done!\n");

    delete dis;
}


void Disassembler::disassemble()
{
    /*
    printf("Writing .crt0...\n");
    writeTextAsm(m_TextFile, m_Nso->getElf64Dyn(DT_INIT)->d_un - m_CurAddr, ".crt0");

    printf("Writing .init...\n");
    writeTextAsm(m_TextFile, m_Nso->getElf64Dyn(DT_FINI)->d_un - m_CurAddr, ".init");
    
    printf("Writing .fini...\n");
    writeTextAsm(m_TextFile, getFiniSize(), ".fini");

    printf("Writing .text...\n");
    writeTextAsm(m_TextFile, getFiniSize(), ".text");
    */



    printf("Writing .rodata...\n");
    writeRodataAsm();
    printf("Writing .data...\n");
    writeDataAsm();
    printf("Writing .bss...\n");
    writeBssAsm();
}


Disassembler::Symbol* Disassembler::getSymbol(size_t addr)
{
    size_t first = 0, last = m_Syms.size();
    if (last == 0)
        return nullptr;
    while (true)
    {
        size_t mid = first + (last - first)/2;
        
        if (m_Syms[mid].m_Addr > addr)
        {
            last = mid;
        }
        else if (m_Syms[mid].m_Addr < addr)
        {
            first = mid;
        }
        else
        {
            first = last = mid;
            while (first > 0 && m_Syms[first-1].m_Addr == m_Syms[mid].m_Addr)
                first--;
            
            while (last < m_Syms.size()-1 && m_Syms[last+1].m_Addr == m_Syms[mid].m_Addr)
                last++;

            return &m_Syms[first];
        }
            
        if (first+1 == last)
        {
            if (m_Syms[last].m_Addr != addr)
                last--;
        }
        
        if (first == last)
            return (m_Syms[first].m_Addr == addr) ? &m_Syms[first] : nullptr;
        
    }
    
}

size_t xRegIdx(u32 reg)
{
    switch (reg)
    {
    case ARM64_REG_X0...ARM64_REG_X28:
        return reg - ARM64_REG_X0;
    case ARM64_REG_X29...ARM64_REG_X30: 
        return reg - ARM64_REG_X29 + 29;
    default:
        return SIZE_MAX;
    }
}

void Disassembler::findSymRefs()
{
    cs_insn* ins;
    SymRef* adrps[30] = {0};
    
    size_t curAddr = m_Nso->m_Header.text.addr;
    size_t endAddr = curAddr + m_Nso->m_Header.text.size;

    while (curAddr < endAddr)
    {   
        size_t count = cs_disasm(m_Handle, m_Nso->text<u8>(curAddr), endAddr - curAddr, curAddr, 0, &ins);
        for (size_t i = 0; i < count; i++)
        {
            cs_arm64_op* ops = ins[i].detail->arm64.operands;

            switch (ins[i].id)
            {
            case ARM64_INS_ADRP:
                m_SymRefs.push_back({ ins[i].address, static_cast<u32>(ops[1].imm) });
                adrps[xRegIdx(ops[0].reg)] = &m_SymRefs[m_SymRefs.size()-1];
                break;

            case ARM64_INS_ADD:
                if (ins[i].detail->arm64.op_count == 3 &&
                    ops[0].type == ops[1].type == ARM64_OP_REG &&
                    ops[2].type == ARM64_OP_IMM &&
                    ops[1].reg >= ARM64_REG_X0 &&
                    ops[1].reg <= ARM64_REG_X28 &&
                    adrps[xRegIdx(ops[1].reg)] != nullptr)
                {
                    auto adrpRef = adrps[xRegIdx(ops[1].reg)];
                    adrpRef->addr += ops[2].imm;
                    m_SymRefs.push_back({ ins[i].address, adrpRef->addr });
                    adrps[xRegIdx(ops[1].reg)] = nullptr;
                }
                break;
            case ARM64_INS_LDR:
                if (ins[i].detail->arm64.op_count == 2 &&
                    ops[0].type == ARM64_OP_REG &&
                    ops[1].type == ARM64_OP_MEM &&
                    ops[1].mem.base >= ARM64_REG_X0 &&
                    ops[1].mem.base <= ARM64_REG_X28 &&
                    adrps[xRegIdx(ops[1].mem.base)] != nullptr)
                {
                    auto adrpRef = adrps[xRegIdx(ops[1].reg)];
                    adrpRef->addr += ops[1].mem.disp;
                    m_SymRefs.push_back({ ins[i].address, adrpRef->addr });
                    adrps[xRegIdx(ops[1].mem.base)] = nullptr;
                }
                break;
            case ARM64_INS_B:
            case ARM64_INS_BL:
                m_SymRefs.push_back({ ins[i].address, static_cast<u32>(ops[0].imm) });
                break;

            case ARM64_INS_CBNZ:
            case ARM64_INS_CBZ:
                m_SymRefs.push_back({ ins[i].address, static_cast<u32>(ops[1].imm) });
                break;

            case ARM64_INS_TBZ:
            case ARM64_INS_TBNZ:
                m_SymRefs.push_back({ ins[i].address, static_cast<u32>(ops[2].imm) });
                break;

            default:
                break;
            }
        }

        cs_free(ins, count);
        curAddr += count * 4;
        if (curAddr < endAddr)
            curAddr += 4;
    }

}

void Disassembler::generateSymbols()
{
    // add elf64 syms
    auto symTab = m_Nso->rodata<Elf64_Sym>(m_Nso->m_Header.dynSym.off);
    for (size_t i = 0; i < m_Nso->m_Header.dynSym.size / sizeof(Elf64_Sym); i++)
        if (ELF64_ST_TYPE(symTab[i].st_info) == STT_OBJECT || ELF64_ST_TYPE(symTab[i].st_info) == STT_FUNC)
            m_Syms.push_back(Disassembler::Symbol(symTab + i, m_Nso));

    // sort m_Syms and m_SymRefs for better performances
    std::sort(m_Syms.begin(), m_Syms.end(),
        [](const Disassembler::Symbol& a, const Disassembler::Symbol& b) -> bool {
            return a.m_Addr < b.m_Addr;
        }
    );
    std::sort(m_SymRefs.begin(), m_SymRefs.end(),
        [](const Disassembler::SymRef& a, const Disassembler::SymRef& b) -> bool {
            return a.addr < b.addr;
        }
    );

    // add m_SymRefs that don't already exist
    size_t oldSize = m_Syms.size();
    bool lastState = true;
    {
        size_t i = 0, j = 0;
        
        while (i+1 < m_SymRefs.size() && m_SymRefs[i].addr == m_SymRefs[i+1].addr)
            i++;
        while (j+1 < oldSize && m_Syms[j].m_Addr == m_Syms[j+1].m_Addr)
            j++;

        while(i < m_SymRefs.size())
        {
            if (j >= oldSize || m_SymRefs[i].addr < m_Syms[j].m_Addr)
            {
                m_Syms.push_back(Disassembler::Symbol(m_SymRefs[i].addr, m_Nso));

                i++;
                while (m_SymRefs[i].addr == m_SymRefs[i+1].addr)
                    i++;
            }
            else if (m_SymRefs[i].addr > m_Syms[j].m_Addr)
            {
                j++;
                while (m_Syms[j].m_Addr == m_Syms[j+1].m_Addr)
                    j++;
            }
            else if (m_SymRefs[i].addr == m_Syms[j].m_Addr)
            {
                i++;
                while (m_SymRefs[i].addr == m_SymRefs[i+1].addr)
                    i++;
                j++;
                while (m_Syms[j].m_Addr == m_Syms[j+1].m_Addr)
                    j++;
            }
        }
    }

    // sort m_Syms
    std::sort(m_Syms.begin(), m_Syms.end(),
        [](const Disassembler::Symbol& a, const Disassembler::Symbol& b) -> bool {
            return a.m_Addr < b.m_Addr;
        }
    );

   // sort m_SymRefs
   std::sort(m_SymRefs.begin(), m_SymRefs.end(),
        [](const Disassembler::SymRef& a, const Disassembler::SymRef& b) -> bool {
            return a.insAddr < b.insAddr;
        }
    );
}

void Disassembler::writeTextAsm(FILE* file, size_t size, const char* sectionName)
{
    fprintf(file, ".section %s, \"ax\", %%progbits\n\n", sectionName);

    cs_insn* ins;

    size_t endAddr = m_CurAddr + size;

    while (m_CurAddr < endAddr)
    {
        size_t count = cs_disasm(m_Handle, m_Nso->text<u8>(m_CurAddr), endAddr - m_CurAddr, m_CurAddr, 0, &ins);
        size_t j = 0;
        for (size_t i = 0; i < count; i++) {
            cs_arm64_op* ops = ins[i].detail->arm64.operands;

            // write label
            auto curSym = getSymbol(ins[i].address);
            if (curSym)
                fprintf(file, "%s:\n", curSym->m_Name.c_str());
            // write mnemonic
            fprintf(file, "/* 0x%08lx */ %s ", ins[i].address, ins[i].mnemonic);


            while (j < m_SymRefs.size() && m_SymRefs[j].insAddr < ins[i].address)
                j++;

            // write operands with sym
            if (
                (ins[i].id == ARM64_INS_ADRP ||
                ins[i].id == ARM64_INS_LDR ||
                ins[i].id == ARM64_INS_ADD ||
                ins[i].id == ARM64_INS_B ||
                ins[i].id == ARM64_INS_BL ||
                ins[i].id == ARM64_INS_CBNZ ||
                ins[i].id == ARM64_INS_CBZ ||
                ins[i].id == ARM64_INS_TBZ ||
                ins[i].id == ARM64_INS_TBNZ) &&

                (j < m_SymRefs.size() && m_SymRefs[j].insAddr == ins[i].address)
            )
            {
                const char* targetSym = getSymbol(m_SymRefs[j].addr)->m_Name.c_str();
                switch (ins[i].id)
                {
                case ARM64_INS_ADRP:
                    // adrp x21, #0x3000
                    fprintf(file, "%s, %s\n", cs_reg_name(m_Handle, ops[0].reg), targetSym);
                    break;
                case ARM64_INS_LDR:
                    // ldr x21, [x21, #0x198]
                    fprintf(file, "%s, [%s, #:lo12:%s]\n", cs_reg_name(m_Handle, ops[0].reg), cs_reg_name(m_Handle, ops[1].mem.base), targetSym);
                    break;
                case ARM64_INS_ADD:
                    // add x8, x8, #0x100
                    fprintf(file, "%s, %s, #:lo12:%s\n", cs_reg_name(m_Handle, ops[0].reg), cs_reg_name(m_Handle, ops[1].reg), targetSym);
                    break;
                case ARM64_INS_B:
                case ARM64_INS_BL:
                    fprintf(file, "%s\n", targetSym);
                    break;

                case ARM64_INS_CBNZ:
                case ARM64_INS_CBZ:
                    // cbz x2, #0x478
                    fprintf(file, "%s, %s\n", cs_reg_name(m_Handle, ops[0].reg), targetSym);
                    break;
                case ARM64_INS_TBZ:
                case ARM64_INS_TBNZ:
                    // tbnz w0, #0x1f, #0x400006eec
                    fprintf(file, "%s, #0x%lx, %s\n", cs_reg_name(m_Handle, ops[0].reg), ops[1].imm, targetSym);
                    break;
                
                default:
                    throw std::runtime_error("???");
                }
            }
            else 
            {
                // write operands normal
                fprintf(file, "%s\n", ins[i].op_str);
                if (ins[i].id == ARM64_INS_RET)
                    fprintf(file, "\n");
            }
        }
    
        
        cs_free(ins, count);
        m_CurAddr += count*4;
        if (m_CurAddr < endAddr)
        {
            fprintf(file, "\n/* 0x%08lx */ .word 0x%08X\n\n", m_CurAddr, *m_Nso->text<u32>(m_CurAddr));
            m_CurAddr += 4;
        }
    }
    
    fprintf(file, "\n");
}

void Disassembler::writeRodataAsm()
{
    fprintf(m_TextFile, ".section .rodata, \"a\", %%progbits\n\n");

    for (size_t i = 0; i < m_Syms.size(); i++)
    {
        if (m_Syms[i].m_Addr >= m_Nso->m_Header.rodata.addr && m_Syms[i].m_Addr < m_Nso->m_Header.rodata.addr + m_Nso->m_Header.rodata.size)
        {
            fprintf(m_TextFile, "/* 0x%08lX */\n", m_Syms[i].m_Addr);
            fprintf(m_TextFile, "%s:\n", m_Syms[i].m_Name.c_str());
            for (size_t j = i+1; j < m_Syms.size(); j++)
            {
                if (m_Syms[i].m_Addr == m_Syms[j].m_Addr)
                {
                    fprintf(m_TextFile, "%s:\n", m_Syms[j].m_Name.c_str());
                    i = j;
                }
            }
            fprintf(m_TextFile, "\n");
        }
    }
    fprintf(m_TextFile, "\n");
}

void Disassembler::writeDataAsm()
{
    fprintf(m_TextFile, ".section .data, \"aw\", %%progbits\n\n");

    for (size_t i = 0; i < m_Syms.size(); i++)
    {
        if (m_Syms[i].m_Addr >= m_Nso->m_Header.data.addr && m_Syms[i].m_Addr < m_Nso->m_Header.data.addr + m_Nso->m_Header.data.size)
        {
            fprintf(m_TextFile, "/* 0x%08lX */\n", m_Syms[i].m_Addr);
            fprintf(m_TextFile, "%s:\n", m_Syms[i].m_Name.c_str());
            for (size_t j = i+1; j < m_Syms.size(); j++)
            {
                if (m_Syms[i].m_Addr == m_Syms[j].m_Addr)
                {
                    fprintf(m_TextFile, "%s:\n", m_Syms[j].m_Name.c_str());
                    i = j;
                }
            }
            fprintf(m_TextFile, "\n");
        }
    }
    fprintf(m_TextFile, "\n");
}

void Disassembler::writeBssAsm()
{
    fprintf(m_TextFile, ".section .bss,\"aw\"\n\n");

    u32 bssStart = m_Nso->m_Header.data.addr + m_Nso->m_Header.data.size;
    for (size_t i = 0; i < m_Syms.size(); i++)
    {
        if (m_Syms[i].m_Addr >= bssStart && m_Syms[i].m_Addr < bssStart + m_Nso->m_Header.bssSize)
        {
            fprintf(m_TextFile, "/* 0x%08lX */\n", m_Syms[i].m_Addr);
            fprintf(m_TextFile, "%s:\n", m_Syms[i].m_Name.c_str());
            for (size_t j = i+1; j < m_Syms.size(); j++)
            {
                if (m_Syms[i].m_Addr == m_Syms[j].m_Addr)
                {
                    fprintf(m_TextFile, "%s:\n", m_Syms[j].m_Name.c_str());
                    i = j;
                }
            }
            fprintf(m_TextFile, "\n");
        }
    }
    fprintf(m_TextFile, "\n");
}