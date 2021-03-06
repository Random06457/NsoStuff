#include <exception>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include "Disassembler.hpp"

#define CODE_BUF_SIZE    0x1000
#define ELEMENT_EXISTS(vec, element) (std::find(vec.begin(), vec.end(), element) != vec.end())

Disassembler::Disassembler(NsoFile* nso, std::string asmDir) :
    m_Nso(nso),
    m_AsmDir(asmDir),
    m_Handle(0),
    m_SymRefs(),
    m_Syms(),
    m_SectionHandlers()
{

    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &m_Handle) != CS_ERR_OK)
        throw std::runtime_error("cs_open failed");

    cs_option(m_Handle, CS_OPT_DETAIL, CS_OPT_ON);
}

Disassembler::~Disassembler()
{
    cs_close(&m_Handle);
}

void Disassembler::process(NsoFile* nso, std::string asmDir)
{
    Disassembler* dis = new Disassembler(nso, asmDir);

    printf("Finding Symbol References...\n");
    dis->findSymRefs();

    printf("Generating Symbol List...\n");
    dis->generateSymbols();

    printf("Writing linker script...\n");
    dis->writeLd();

    printf("Disassembling...\n");
    dis->disassemble();

    printf("Done!\n");

    delete dis;
}

void Disassembler::writeLd()
{
    FILE* f = fopen((m_AsmDir + "/app.ld").c_str(), "wb");

    fprintf(f, "OUTPUT_FORMAT(elf64-littleaarch64)\n");
    fprintf(f, "OUTPUT_ARCH(aarch64)\n");
    fprintf(f, "\n");

    fprintf(f, "PHDRS\n");
    fprintf(f, "{\n");
    fprintf(f, "    text PT_LOAD FLAGS(5);\n");
    fprintf(f, "    rodata PT_LOAD FLAGS(4);\n");
    fprintf(f, "    data PT_LOAD FLAGS(6);\n");
    fprintf(f, "    dynamic PT_DYNAMIC;\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");

    fprintf(f, "SECTIONS\n");
    fprintf(f, "{\n");
    fprintf(f, "    PROVIDE(__start__ = 0x0);\n");
    fprintf(f, "    . = __start__;\n");
    fprintf(f, "\n");

    for (auto s : m_Nso->m_Sections)
    {
        if (s.isPadding())
        {
            fprintf(f, "\n");
            fprintf(f, "    . = ALIGN(0x%lX);\n", s.m_Align);
            fprintf(f, "\n");
        }
        else
        {
            std::string curSeg;
            switch (m_Nso->getSegmentType(s.start()))
            {
            case NsoFile::SegmentType::text:
                curSeg = "text";
                break;
            case NsoFile::SegmentType::rodata:
                curSeg = "rodata";
                break;
            case NsoFile::SegmentType::data:
            case NsoFile::SegmentType::bss:
                curSeg = "data";
                break;
            
            default:
                throw std::runtime_error("Invalid Segment");
            }
            fprintf(f, "    %s : { *(%s) } :%s\n", s.name().c_str(), s.name().c_str(), curSeg.c_str());
        }
    }
    fprintf(f, "\n");
    fprintf(f, "    __end__ = ABSOLUTE(.);\n");
    fprintf(f, "}\n");

    fclose(f);
}

void Disassembler::disassemble()
{
    FILE* f;
    NsoFile::Section* s;

    /* .text sections */

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".crt0", "ax", true, [this] (FILE* f, NsoFile::Section* s) {
        writeTextAsm(f, s->start(), 4);
        fprintf(f, "/* %08lX */ .word __mod0_start\n\n", s->start()+4);
        writeTextAsm(f, s->start()+8, s->size()-8);
    }));

    addTextSectionHandler(".init");
    addTextSectionHandler(".fini");
    addTextSectionHandler(".plt");
    addTextSectionHandler(".text");
    addTextSectionHandler(".text2");

    /* .rodata sections */ 

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".module_name", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        fprintf(f, ".word 0x%X\n", *m_Nso->mem<u32>(s->start() + 0));
        char* name = m_Nso->mem<char>(s->start() + 8);
        u32 nameSize = *m_Nso->mem<u32>(s->start() + 4);
        u32 calcNameSize = strlen(name);
        if (nameSize == calcNameSize)
            fprintf(f, ".word module_name_len\n");
        else
            fprintf(f, ".word 0x%X\n", nameSize);
        
        fprintf(f, "module_name: .asciz \"%s\"\n", name);
        if (nameSize == calcNameSize)
            fprintf(f, "module_name_len = . - module_name - 1\n");
    }));

    
    addRelaSectionHandler(".rela.dyn");
    addRelaSectionHandler(".rela.plt");

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".hash", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        auto hash = m_Nso->mem<Elf64_Hash>(s->start());
        fprintf(f, ".word 0x%X /* nbuckets */\n", hash->nbuckets);
        fprintf(f, ".word 0x%X /* nchains */\n", hash->nchains);
        fprintf(f, "\n");
        fprintf(f, "/* bucket */\n");
        for (size_t i = 0; i < hash->nbuckets; i++)
            fprintf(f, ".word 0x%X\n", hash->data[i]);
        fprintf(f, "\n");
        fprintf(f, "/* chain */\n");
        for (size_t i = 0; i < hash->nchains; i++)
            fprintf(f, ".word 0x%X\n", hash->data[hash->nbuckets+i]);
    }));

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".gnu.hash", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        auto hash = m_Nso->mem<Elf64_GnuHash>(s->start());
        fprintf(f, ".word 0x%X /* nbuckets */\n", hash->nbuckets);
        fprintf(f, ".word 0x%X /* symndx */\n", hash->symndx);
        fprintf(f, ".word 0x%X /* maskwords */\n", hash->maskwords);
        fprintf(f, ".word 0x%X /* shift */\n", hash->shift);
        fprintf(f, "\n");

        size_t curSize = sizeof(Elf64_GnuHash);

        u64* indexes = m_Nso->mem<u64>(s->start() + curSize);
        fprintf(f, "/* indexes */\n");
        for (size_t i = 0; i < hash->maskwords; i++)
            fprintf(f, ".quad 0x%llX\n", indexes[i]);
        fprintf(f, "\n");

        curSize += hash->maskwords * sizeof(u64);

        u32* buckets = reinterpret_cast<u32*>(indexes + hash->maskwords);
        fprintf(f, "/* bucket */\n");
        for (size_t i = 0; i < hash->nbuckets; i++)
            fprintf(f, ".word 0x%X\n", buckets[i]);  
        fprintf(f, "\n");

        curSize += hash->nbuckets * sizeof(u32);
        
        // use s->size() - curSize to handle cases where .gnu.hash is invalid (for example sp2 rtld)
        u32* chains = buckets + hash->nbuckets;
        fprintf(f, "/* chain */\n");
        for (size_t i = 0; i < (s->size() - curSize) / sizeof(u32); i++)
            fprintf(f, ".word 0x%X\n", chains[i]);
    }));

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".dynsym", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        Elf64_Sym* sym = m_Nso->mem<Elf64_Sym>(s->start());
        for (size_t i = 0; i < s->size() / sizeof(Elf64_Sym); i++)
        {
            fprintf(f, ".word 0x%X; .byte 0x%X; .byte 0x%X; .hword 0x%X; .quad 0x%llX; .quad 0x%llX\n",
                sym[i].st_name,
                sym[i].st_info,
                sym[i].st_other,
                sym[i].st_shndx,
                sym[i].st_value,
                sym[i].st_size);
        }
    }));
    
    m_SectionHandlers.push_back(Disassembler::SectionHandler(".dynstr", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        
        const char* str = m_Nso->mem<char>(s->start());
        for (size_t i = 0; i < s->size();)
        {
            fprintf(f, ".asciz \"%s\"\n", str + i);
            size_t len = strlen(str + i);
            i += len+1;
        }
    }));


    addDataSectionHandler(".rodata", false, false);

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".eh_frame_hdr", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        auto ehFrameHdr = m_Nso->mem<EhFrameHdr>(s->start());
        fprintf(f, "eh_frame_hdr_start:\n");
        fprintf(f, ".byte 0x%X /* version */\n", ehFrameHdr->version);
        fprintf(f, ".byte 0x%X /* eh_frame_ptr_enc */\n", ehFrameHdr->eh_frame_ptr_enc);
        fprintf(f, ".byte 0x%X /* fde_count_enc */\n", ehFrameHdr->fde_count_enc);
        fprintf(f, ".byte 0x%X /* table_enc */\n", ehFrameHdr->table_enc);
        fprintf(f, ".word 0x%X /* eh_frame_ptr */\n", ehFrameHdr->eh_frame_ptr);
        fprintf(f, ".word 0x%X /* fde_count */\n", ehFrameHdr->fde_count);
        fprintf(f, "\n");
        for (size_t i = 0; i < ehFrameHdr->fde_count; i++)
            fprintf(f, ".word 0x%08X, 0x%08X\n", ehFrameHdr->entries[i].funcAddr, ehFrameHdr->entries[i].fdeAddr);
        
    }));

    addDataSectionHandler(".eh_frame", false, false);
    
    addDataSectionHandler(".misc_start", false, false);

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".mod0", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        fprintf(f, ".word 0\n");
        fprintf(f, ".word 8\n");
        fprintf(f, "__mod0_start:\n");
        fprintf(f, ".ascii \"%c%c%c%c\"\n", m_Nso->m_Mod0->magic.name[0], m_Nso->m_Mod0->magic.name[1], m_Nso->m_Mod0->magic.name[2], m_Nso->m_Mod0->magic.name[3]);
        fprintf(f, ".word 0x%08X\n", m_Nso->m_Mod0->dynOff);
        fprintf(f, ".word 0x%08X\n", m_Nso->m_Mod0->bssStartOff);
        fprintf(f, ".word 0x%08X\n", m_Nso->m_Mod0->bssEndOff);
        fprintf(f, ".word 0x%08X\n", m_Nso->m_Mod0->ehFrameHdrStartOff);
        fprintf(f, ".word 0x%08X\n", m_Nso->m_Mod0->ehFrameHdrEndOff);
        fprintf(f, ".word 0x%08X\n", m_Nso->m_Mod0->modObjectOff);
    }));

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".note.gnu.build-id", "a", true, [this] (FILE* f, NsoFile::Section* s) {
        fprintf(f, ".word 0x%X /* n_namesz */\n", m_Nso->m_GnuBuildIdNote->n_namesz);
        fprintf(f, ".word 0x%X /* n_descsz */\n", m_Nso->m_GnuBuildIdNote->n_descsz);
        fprintf(f, ".word 0x%X /* n_type */\n", m_Nso->m_GnuBuildIdNote->n_type);
        fprintf(f, ".asciz \"%s\"\n", m_Nso->m_GnuBuildIdNote->data);
        if (m_Nso->m_GnuBuildIdNote->n_descsz > 0)
            fprintf(f, ".byte 0x%02X", (u8)m_Nso->m_GnuBuildIdNote->data[m_Nso->m_GnuBuildIdNote->n_namesz]);
        for (size_t i = 1; i < m_Nso->m_GnuBuildIdNote->n_descsz; i++)
            fprintf(f, ",0x%02X", (u8)m_Nso->m_GnuBuildIdNote->data[m_Nso->m_GnuBuildIdNote->n_namesz+i]);
        fprintf(f, "\n");
    }));


    /* .data sections */ 

    addDataSectionHandler(".data", true, false);

    m_SectionHandlers.push_back(Disassembler::SectionHandler(".dynamic", "aw", true, [this] (FILE* f, NsoFile::Section* s) {
        Elf64_Dyn* dyn = m_Nso->mem<Elf64_Dyn>(s->start());
        for (size_t i = 0; i < s->size() / sizeof(Elf64_Dyn); i++)
            fprintf(f, ".quad 0x%llX, 0x%llX /* %s */\n", dyn[i].d_tag, dyn[i].d_un, Elf64_Dyn::getTagName(dyn[i].d_tag));
    }));

    addDataSectionHandler(".got.plt", true, false);
    addDataSectionHandler(".got", true, false);

    addDataSectionHandler(".bss", true, true);

    // process sections:

    f = fopen((m_AsmDir + "/full.s").c_str(), "wb");
    for (auto s: m_Nso->m_Sections)
    {
        if (!s.isPadding())
        {
            bool found = true;
            
            for (auto handler: m_SectionHandlers)
                if (handler.m_Name == s.m_Name)
                {
                    printf("Writing %s...\n", s.name().c_str());
                    fprintf(f,".section %s, \"%s\",%s\n", handler.m_Name.c_str(), handler.m_Perms, handler.m_Progbits ? "%progbits" : "%nobits");
                    handler.m_Handler(f, &s);
                    fprintf(f, "\n\n");
                    found = true;
                    break;
                }
            if (!found)
            {
                printf("could not find %s\n", s.m_Name.c_str());
                throw std::runtime_error("Unsupported Section");
            }
        }
    }
    
    fclose(f);
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


void Disassembler::addTextSectionHandler(const char* name)
{
    m_SectionHandlers.push_back(Disassembler::SectionHandler(name, "ax", true, [this] (FILE* f, NsoFile::Section* s) {
        writeTextAsm(f, s->start(), s->size());
    }));
}
void Disassembler::addDataSectionHandler(const char* name, bool writable, bool bss)
{
    m_SectionHandlers.push_back(Disassembler::SectionHandler(name, writable ? "aw" : "a", !bss, [this, bss] (FILE* f, NsoFile::Section* s) {
        writeDataAsm(f, s->start(), s->size(), bss);
    }));
}


void Disassembler::addRelaSectionHandler(const char* name)
{
    m_SectionHandlers.push_back(Disassembler::SectionHandler(name, "a", true, [this] (FILE* f, NsoFile::Section* s) {
        Elf64_Rela* rela = m_Nso->mem<Elf64_Rela>(s->start());
        for (size_t i = 0; i < s->size() / sizeof(Elf64_Rela); i++)
            fprintf(f, ".quad 0x%llX, 0x%llX, 0x%llX\n", rela[i].r_offset, rela[i].r_info, rela[i].r_addend);

        // TODO:
        /*
        auto rela = m_Nso->mem<Elf64_Rela>(s->start());

        struct RelaEntry
        {
            Elf64_Rela* relaPtr;
            Disassembler::Symbol* symPtr;
        };

        // create a vector to sort Elf64_Rela entries
        std::vector<RelaEntry> relas;
        for (size_t i = 0; i < s->size()/sizeof(Elf64_Rela); i++)
            relas.push_back({ rela + i, nullptr });

        // sort with r_addend to add Disassembly::Symbols more efficiently
        std::sort(relas.begin(), relas.end(),
            [](const Elf64_Rela* a, const Elf64_Rela* b) -> bool {
                return a->r_addend < b->r_addend;
            }
        );

        // sort with r_offset
        std::sort(relas.begin(), relas.end(),
            [](const Elf64_Rela* a, const Elf64_Rela* b) -> bool {
                return a->r_offset < b->r_offset;
            }
        );

        for (size_t addr = s->start(); addr < s->end(); addr += sizeof(Elf64_Rela))
        {
            while(rela->r_offset < addr)
                rela++;
            
            if (addr == rela->r_offset)
            {
                fprintf(f, ".word ");
            }
            else
            {
                fprintf(f, ".word 0x%08X \n");
            }
        }
        */
    }));
}

void Disassembler::writeTextAsm(FILE* f, size_t start, size_t size)
{
    cs_insn* ins;

    size_t endAddr = start + size;
    size_t cur = start;

    while (cur < endAddr)
    {
        size_t count = cs_disasm(m_Handle, m_Nso->text<u8>(cur), endAddr - cur, cur, 0, &ins);
        size_t j = 0;
        for (size_t i = 0; i < count; i++) {
            cs_arm64_op* ops = ins[i].detail->arm64.operands;

            // write label
            auto curSym = getSymbol(ins[i].address);
            if (curSym)
                fprintf(f, "%s:\n", curSym->m_Name.c_str());
            // write mnemonic
            fprintf(f, "/* 0x%08lx */ %s ", ins[i].address, ins[i].mnemonic);


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
                    fprintf(f, "%s, %s\n", cs_reg_name(m_Handle, ops[0].reg), targetSym);
                    break;
                case ARM64_INS_LDR:
                    // ldr x21, [x21, #0x198]
                    fprintf(f, "%s, [%s, #:lo12:%s]\n", cs_reg_name(m_Handle, ops[0].reg), cs_reg_name(m_Handle, ops[1].mem.base), targetSym);
                    break;
                case ARM64_INS_ADD:
                    // add x8, x8, #0x100
                    fprintf(f, "%s, %s, #:lo12:%s\n", cs_reg_name(m_Handle, ops[0].reg), cs_reg_name(m_Handle, ops[1].reg), targetSym);
                    break;
                case ARM64_INS_B:
                case ARM64_INS_BL:
                    fprintf(f, "%s\n", targetSym);
                    break;

                case ARM64_INS_CBNZ:
                case ARM64_INS_CBZ:
                    // cbz x2, #0x478
                    fprintf(f, "%s, %s\n", cs_reg_name(m_Handle, ops[0].reg), targetSym);
                    break;
                case ARM64_INS_TBZ:
                case ARM64_INS_TBNZ:
                    // tbnz w0, #0x1f, #0x400006eec
                    fprintf(f, "%s, #0x%lx, %s\n", cs_reg_name(m_Handle, ops[0].reg), ops[1].imm, targetSym);
                    break;
                
                default:
                    throw std::runtime_error("???");
                }
            }
            else 
            {
                // write operands normal
                fprintf(f, "%s\n", ins[i].op_str);
                if (ins[i].id == ARM64_INS_RET)
                    fprintf(f, "\n");
            }

            cur += ins[i].size;
        }
    
        
        cs_free(ins, count);
        if (cur < endAddr)
        {
            fprintf(f, "\n/* 0x%08lx */ .word 0x%08X\n\n", cur, *m_Nso->text<u32>(cur));
            cur += 4;
        }
    }
}

void Disassembler::writeDataAsm(FILE* f, size_t start, size_t size, bool bss)
{
    // todo: add refs (from Elf64_Rela)

    size_t symIdx = 0;
    for (size_t addr = start; addr < start + size;)
    {
        while (symIdx < m_Syms.size() && m_Syms[symIdx].m_Addr < addr)
            symIdx++;
        
        // add label
        if (addr == m_Syms[symIdx].m_Addr)
            fprintf(f, "%s:\n", m_Syms[symIdx].m_Name.c_str());
        

        // address
        fprintf(f, "/* 0x%08lX */ ", addr);
        fprintf(f, ".byte 0x%02X\n", *m_Nso->mem<u8>(addr++));
    }
    
    /*
    // this is temporary
    for (size_t i = 0; i < m_Syms.size(); i++)
    {
        if (m_Syms[i].m_Addr >= start && m_Syms[i].m_Addr < start + size)
        {
            fprintf(f, "/_* 0x%08lX *_/\n", m_Syms[i].m_Addr);
            fprintf(f, "%s:\n", m_Syms[i].m_Name.c_str());
            for (size_t j = i+1; j < m_Syms.size(); j++)
            {
                if (m_Syms[i].m_Addr == m_Syms[j].m_Addr)
                {
                    fprintf(f, "%s:\n", m_Syms[j].m_Name.c_str());
                    i = j;
                }
            }
            fprintf(f, "\n");
        }
    }
    fprintf(f, "\n");
    */
}