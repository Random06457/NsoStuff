#include "ElfConvert.hpp"
#include "NsoFile.hpp"


size_t getFileOff(NsoFile* nso, NsoFile::Section* s, size_t contentStart)
{
    auto type = nso->getSegmentType(s->start());

    size_t textStart = contentStart;
    size_t roStart = textStart + nso->m_Header.text.size;
    size_t rwStart = roStart + nso->m_Header.rodata.size;

    switch (type)
    {
    case NsoFile::SegmentType::text: return (s->start() - nso->m_Header.text.addr) + textStart;
    case NsoFile::SegmentType::rodata: return (s->start() - nso->m_Header.rodata.addr) + roStart;
    case NsoFile::SegmentType::data:
    case NsoFile::SegmentType::bss: return (s->start() - nso->m_Header.data.addr) + rwStart;
    }
    
    throw std::runtime_error("invalid segment type");
}

void ElfConvert::nso2elf(NsoFile* nso, std::string elfPath)
{
    auto ehFrame = nso->getSection(".eh_frame");
    auto dynamic = nso->getSection(".dynamic");
    auto note = nso->getSection(".note.gnu.build-id");

    u16 phCount = 3 + (!!ehFrame) + (!!dynamic) + (!!note);

    std::vector<NsoFile::Section*> sections;

    // get the shstrtab size / the section count

    u16 shCount = 2; // null + shstrtab
    size_t shStrTabSize = 1 + strlen(".shstrtab") + 1;
    for (auto& s : nso->m_Sections)
    {
        if (!s.isPadding())
        {
            sections.push_back(&s);
            shCount++;
            shStrTabSize += s.m_Name.size()+1;
        }
    }
    shStrTabSize = ALIGN4(shStrTabSize);

    char* shStrTab = new char[shStrTabSize];
    u32 shStrTabIdx = 0;

    size_t contentStart = sizeof(Elf64_Ehdr) + phCount * sizeof(Elf64_Phdr) + shCount * sizeof(Elf64_Shdr) + shStrTabSize;

    Elf64_Ehdr ehdr = {
        .e_ident =
        {
            .magic = ELF_MAGIC,
            .elf_class = ELFCLASS64,
            .bytesex = ELFDATA2LSB,
            .version = EV_CURRENT,
            .osabi = ELFOSABI_NONE,
            .abiversion = 0,
            .pad = {0},
        },
        .e_type = ET_DYN,
        .e_machine = EM_AARCH64,
        .e_version = 1,
        .e_entry = 0,
        .e_phoff = sizeof(Elf64_Ehdr),
        .e_shoff = sizeof(Elf64_Ehdr) + phCount * sizeof(Elf64_Phdr),
        .e_flags = 0,
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = phCount,
        .e_shentsize = sizeof(Elf64_Shdr),
        .e_shnum = shCount,
        .e_shstrndx = 1,
    };

    size_t off = contentStart;

    /* Program Headers */

    std::vector<Elf64_Phdr> phdrs;

    // .text
    phdrs.push_back({
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_X,
        .p_offset = off,
        .p_vaddr = nso->m_Header.text.addr,
        .p_paddr = nso->m_Header.text.addr,
        .p_filesz = nso->m_Header.text.size,
        .p_memsz = nso->m_Header.text.size,
        .p_align = 0x100,
    });
    off += nso->m_Header.text.size;
    // .rodata
    phdrs.push_back({
        .p_type = PT_LOAD,
        .p_flags = PF_R,
        .p_offset = off,
        .p_vaddr = nso->m_Header.rodata.addr,
        .p_paddr = nso->m_Header.rodata.addr,
        .p_filesz = nso->m_Header.rodata.size,
        .p_memsz = nso->m_Header.rodata.size,
        .p_align = 0x1,
    });

    off += nso->m_Header.rodata.size;
    // .data/.bss
    phdrs.push_back({
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_W,
        .p_offset = off,
        .p_vaddr = nso->m_Header.data.addr,
        .p_paddr = nso->m_Header.data.addr,
        .p_filesz = nso->m_Header.data.size,
        .p_memsz = nso->m_Header.data.size,
        .p_align = 0x100,
    });
    if (note)
    {
        phdrs.push_back({
            .p_type = PT_NOTE,
            .p_flags = PF_R,
            .p_offset = getFileOff(nso, note, contentStart),
            .p_vaddr = note->start(),
            .p_paddr = note->start(),
            .p_filesz = note->size(),
            .p_memsz = note->size(),
            .p_align = 1,
        });
    }
    if (ehFrame)
    {
        phdrs.push_back({
            .p_type = PT_GNU_EH_FRAME,
            .p_flags = PF_R,
            .p_offset = getFileOff(nso, ehFrame, contentStart),
            .p_vaddr = ehFrame->start(),
            .p_paddr = ehFrame->start(),
            .p_filesz = ehFrame->size(),
            .p_memsz = ehFrame->size(),
            .p_align = 1,
        });
    }
    if (dynamic)
    {
        phdrs.push_back({
        .p_type = PT_DYNAMIC,
        .p_flags = PF_R | PF_W,
        .p_offset = getFileOff(nso, dynamic, contentStart),
        .p_vaddr = nso->m_Header.text.addr,
        .p_paddr = nso->m_Header.text.addr,
        .p_filesz = nso->m_Header.text.size,
        .p_memsz = nso->m_Header.text.size,
        .p_align = 0x100,
        });
    }

    off = contentStart;

    /* Section Headers */
    std::vector<Elf64_Shdr> shdrs;

    size_t shIdx = 0;


    shdrs.push_back({
        .sh_name = shStrTabIdx,
        .sh_type = SHT_NULL,
        .sh_flags = 0,
        .sh_addr = 0,
        .sh_offset = 0,
        .sh_size = 0,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = 0,
        .sh_entsize = 0,
    });
    shStrTab[shStrTabIdx++] = '\0';
    shIdx++;


    shdrs.push_back({
        .sh_name = shStrTabIdx,
        .sh_type = SHT_STRTAB,
        .sh_flags = 0,
        .sh_addr = 0,
        .sh_offset = contentStart - shStrTabSize,
        .sh_size = shStrTabSize,
        .sh_link = 0,
        .sh_info = 0,
        .sh_addralign = 1,
        .sh_entsize = 0,
    });
    strcpy(shStrTab + shStrTabIdx, ".shstrtab");
    shStrTabIdx += strlen(".shstrtab") + 1;
    shIdx++;

#define ADD_SHT(strName, type, flags, link, info, align, entSize) \
    { \
        auto s = nso->getSection(strName); \
        if (s) \
        { \
            shdrs.push_back({ \
                .sh_name = shStrTabIdx, \
                .sh_type = type, \
                .sh_flags = flags, \
                .sh_addr = s->start(), \
                .sh_offset = getFileOff(nso, s, contentStart), \
                .sh_size = s->size(), \
                .sh_link = link, \
                .sh_info = info, \
                .sh_addralign = align, \
                .sh_entsize = entSize, \
            }); \
            strcpy(shStrTab + shStrTabIdx, s->name().c_str()); \
            shStrTabIdx += s->name().size() + 1; \
            shIdx++; \
            \
            for (auto& iter : sections) \
                if (iter == s) \
                    iter = nullptr; \
        } \
    }
    
    u32 dynStrShIdx = shIdx;
    ADD_SHT(".dynstr", SHT_STRTAB, SHF_ALLOC, 0, 0, 1, 0);


    auto dynSym = nso->getSection(".dynsym");
    auto syms = nso->mem<Elf64_Sym>(dynSym->m_Addr);
    u32 lastStb = 0;
    for (size_t i = 0; i < dynSym->size() / sizeof(Elf64_Sym); i++)
        if (ELF64_ST_BIND(syms[i].st_info) == STB_LOCAL)
            lastStb = i;
    

    u32 dynSymShIdx = shIdx;
    ADD_SHT(".dynsym", SHT_DYNSYM, SHF_ALLOC, dynStrShIdx, lastStb+1, 8, sizeof(Elf64_Sym));

    //ADD_SHT(".crt0", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 0, 0, 0);
    //ADD_SHT(".init", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 0, 0, 0);
    //ADD_SHT(".fini", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 0, 0, 0);
    u32 pltShIdx = shIdx;
    ADD_SHT(".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, 0, 0, 0x10, 0x10);
    
    ADD_SHT(".module_name", SHT_PROGBITS, SHF_ALLOC, 0, 0, 0, 0);
    ADD_SHT(".rela.dyn", SHT_RELA, SHF_ALLOC, dynSymShIdx, 0, 8, sizeof(Elf64_Rela));
    ADD_SHT(".rela.plt", SHT_RELA, SHF_ALLOC, dynSymShIdx, pltShIdx, 8, sizeof(Elf64_Rela));
    ADD_SHT(".hash", SHT_HASH, SHF_ALLOC, dynSymShIdx, 0, 8, sizeof(u32));
    ADD_SHT(".gnu.hash", SHT_GNU_HASH, SHF_ALLOC, dynSymShIdx, 0, 8, sizeof(u32));
    // rodata
    ADD_SHT(".eh_frame_hdr", SHT_PROGBITS, SHF_ALLOC, 0, 0, 4, 0);
    ADD_SHT(".eh_frame", SHT_PROGBITS, SHF_ALLOC, 0, 0, 4, 0);
    // misc_start
    // mod0
    auto nHdr = nso->mem<Elf64_Nhdr>(note->start());
    ADD_SHT(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC, 0, 0, 4, sizeof(Elf64_Nhdr) + nHdr->n_descsz + nHdr->n_namesz);

    // data
    ADD_SHT(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynStrShIdx, 0, 0, sizeof(Elf64_Dyn));
    ADD_SHT(".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 8, sizeof(u64));
    ADD_SHT(".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 8, sizeof(u64));
    // bss

    // process the remaining sections
    for (auto iter : sections)
    {
        if (iter)
        {
            auto type = nso->getSegmentType(iter->start());
            
            u32 shType = type == NsoFile::SegmentType::bss ? SHT_NOBITS : SHT_PROGBITS;
            u64 flag = SHF_ALLOC |
                ((type == NsoFile::SegmentType::text)
                ? SHF_EXECINSTR :
                (type == NsoFile::SegmentType::data || type == NsoFile::SegmentType::bss)
                    ? SHF_WRITE :
                    0);
                    
            ADD_SHT(iter->name().c_str(), shType, flag, 0, 0, 0, 0);
        }
    }

    FILE* f = fopen(elfPath.c_str(), "wb");

    fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, f);

    for (auto phdr : phdrs)
        fwrite(&phdr, sizeof(Elf64_Phdr), 1, f);
        
    for (auto shdr : shdrs)
        fwrite(&shdr, sizeof(Elf64_Shdr), 1, f);

    fwrite(shStrTab, shStrTabSize, 1, f);

    fwrite(nso->text<char>(), nso->m_Header.text.size, 1, f);
    fwrite(nso->rodata<char>(), nso->m_Header.rodata.size, 1, f);
    fwrite(nso->data<char>(), nso->m_Header.data.size, 1, f);

    fclose(f);

    delete[] shStrTab;
}

