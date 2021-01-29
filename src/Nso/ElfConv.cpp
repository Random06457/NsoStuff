#include "NsoFile.hpp"
#include <assert.h>

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
    case NsoFile::SegmentType::data: return (s->start() - nso->m_Header.data.addr) + rwStart;
    case NsoFile::SegmentType::bss: return 0;
    default: throw std::runtime_error("invalid segment type");
    }
}

void NsoFile::writeELF(std::string path)
{
    auto ehFrame = getSection(".eh_frame");
    auto dynamic = getSection(".dynamic");
    auto note = getSection(".note.gnu.build-id");

    u16 phCount = 3 + (!!ehFrame) + (!!dynamic) + (!!note);

    std::vector<NsoFile::Section*> sections;

    // get the shstrtab size / the section count

    u16 shCount = 2; // null + shstrtab
    size_t shStrTabSize = 1 + strlen(".shstrtab") + 1;
    for (auto& s : m_Sections)
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
        .p_vaddr = m_Header.text.addr,
        .p_paddr = m_Header.text.addr,
        .p_filesz = m_Header.text.size,
        .p_memsz = m_Header.text.size,
        .p_align = 0x100,
    });
    off += m_Header.text.size;
    // .rodata
    phdrs.push_back({
        .p_type = PT_LOAD,
        .p_flags = PF_R,
        .p_offset = off,
        .p_vaddr = m_Header.rodata.addr,
        .p_paddr = m_Header.rodata.addr,
        .p_filesz = m_Header.rodata.size,
        .p_memsz = m_Header.rodata.size,
        .p_align = 0x1,
    });

    off += m_Header.rodata.size;
    // .data/.bss
    phdrs.push_back({
        .p_type = PT_LOAD,
        .p_flags = PF_R | PF_W,
        .p_offset = off,
        .p_vaddr = m_Header.data.addr,
        .p_paddr = m_Header.data.addr,
        .p_filesz = m_Header.data.size,
        .p_memsz = m_Header.data.size,
        .p_align = 0x100,
    });
    if (note)
    {
        phdrs.push_back({
            .p_type = PT_NOTE,
            .p_flags = PF_R,
            .p_offset = getFileOff(this, note, contentStart),
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
            .p_offset = getFileOff(this, ehFrame, contentStart),
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
        .p_offset = getFileOff(this, dynamic, contentStart),
        .p_vaddr = dynamic->start(),
        .p_paddr = dynamic->start(),
        .p_filesz = dynamic->size(),
        .p_memsz = dynamic->size(),
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
        auto s = getSection(strName); \
        if (s) \
        { \
            shdrs.push_back({ \
                .sh_name = shStrTabIdx, \
                .sh_type = type, \
                .sh_flags = flags, \
                .sh_addr = s->start(), \
                .sh_offset = getFileOff(this, s, contentStart), \
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


    auto dynSym = getSection(".dynsym");
    auto syms = mem<Elf64_Sym>(dynSym->m_Addr);
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
    auto nHdr = mem<Elf64_Nhdr>(note->start());
    ADD_SHT(".note.gnu.build-id", SHT_NOTE, SHF_ALLOC, 0, 0, 4, sizeof(Elf64_Nhdr) + nHdr->n_descsz + nHdr->n_namesz);

    // data
    ADD_SHT(".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, dynStrShIdx, 0, 0, sizeof(Elf64_Dyn));
    ADD_SHT(".got.plt", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 8, sizeof(u64));
    ADD_SHT(".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, 0, 0, 8, sizeof(u64));

    // process the remaining sections
    for (auto iter : sections)
    {
        if (iter)
        {
            auto type = getSegmentType(iter->start());
            
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

    FILE* f = fopen(path.c_str(), "wb");

    fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, f);

    for (auto phdr : phdrs)
        fwrite(&phdr, sizeof(Elf64_Phdr), 1, f);
        
    for (auto shdr : shdrs)
        fwrite(&shdr, sizeof(Elf64_Shdr), 1, f);

    fwrite(shStrTab, shStrTabSize, 1, f);

    fwrite(text<char>(), m_Header.text.size, 1, f);
    fwrite(rodata<char>(), m_Header.rodata.size, 1, f);
    fwrite(data<char>(), m_Header.data.size, 1, f);

    fclose(f);

    delete[] shStrTab;
}

void NsoFile::loadELF(std::string path)
{
    FILE* f = fopen(path.c_str(), "rb");
    
    Elf64_Ehdr ehdr;
    fread(&ehdr, 1, sizeof(Elf64_Ehdr), f);
    assert(ehdr.e_ident.magic == ELF_MAGIC);
    assert(ehdr.e_ident.elf_class == ELFCLASS64);
    assert(ehdr.e_ident.bytesex == ELFDATA2LSB);
    assert(ehdr.e_ident.version == EV_CURRENT);
    assert(ehdr.e_type == ET_DYN);
    assert(ehdr.e_machine == EM_AARCH64);
    assert(ehdr.e_version == 1);

    
    /* initialize some header fields */
    m_Header.magic.value = STR_TO_U32('N', 'S', 'O', '0');
    m_Header.version = 0;
    m_Header.reserved = 0;
    m_Header.textHashCheck = true;
    m_Header.rodataHashCheck = true;
    m_Header.dataHashCheck = true;
    memset(m_Header.buildID.data, 0, sizeof(m_Header.buildID));


    /* read out the Phdr / Shdr arrays */
    std::vector<Elf64_Phdr> phdrs(ehdr.e_phnum);
    std::vector<Elf64_Shdr> shdrs(ehdr.e_shnum);

    fseek(f, ehdr.e_phoff, SEEK_SET);
    fread(phdrs.data(), sizeof(Elf64_Phdr), ehdr.e_phnum, f);

    fseek(f, ehdr.e_shoff, SEEK_SET);
    fread(shdrs.data(), sizeof(Elf64_Shdr), ehdr.e_shnum, f);


    /* allocates program memory */
    size_t memSize = 0;
    for (auto& phdr : phdrs)
        memSize = std::max(memSize, static_cast<size_t>(phdr.p_vaddr + phdr.p_memsz));

    memSize = ALIGN_MEM(memSize);
    m_Mem.resize(memSize);

    bool noteFound = false;

    /* process segments */
    for (auto& phdr : phdrs)
    {
        if (phdr.p_type == PT_LOAD)
        {
            fseek(f, phdr.p_offset, SEEK_SET);
            fread(m_Mem.data() + phdr.p_vaddr, 1, phdr.p_filesz, f);

            switch (phdr.p_flags)
            {
            // .text
            case PF_R | PF_X:
                m_Header.text.addr = phdr.p_vaddr;
                m_Header.text.size = phdr.p_memsz;
                break;

            // .rodata
            case PF_R:
                m_Header.rodata.addr = phdr.p_vaddr;
                m_Header.rodata.size = phdr.p_memsz;
                break;

            // .data
            case PF_R | PF_W:
                m_Header.data.addr = phdr.p_vaddr;
                m_Header.data.size = phdr.p_memsz;
                break;
            
            default:
                break;
            }
        }
        else if (phdr.p_type == PT_NOTE)
        {
            Elf64_Nhdr nHdr;
            fseek(f, phdr.p_offset, SEEK_SET);
            fread(&nHdr, 1, sizeof(Elf64_Nhdr), f);

            char* noteBuff = new char[nHdr.n_namesz + nHdr.n_descsz];
            fread(noteBuff, 1, nHdr.n_namesz + nHdr.n_descsz, f);
            
            if (!strncmp(noteBuff, "GNU", nHdr.n_namesz))
            {
                memcpy(m_Header.buildID.data, noteBuff + nHdr.n_namesz, std::min(nHdr.n_descsz, (u32)sizeof(m_Header.buildID)));
                noteFound = true;
            }

            delete[] noteBuff;
        }
    }

    /* find specific sections to fill the nso header */
    Elf64_Shdr* bssShdr = nullptr;
    Elf64_Shdr* dynStrShdr = nullptr;
    Elf64_Shdr* dynSymShdr = nullptr;
    Elf64_Shdr* apiInfoShdr = nullptr;
    char* strTab = nullptr;

    /* first, find the strtab */
    for (auto& shdr : shdrs)
        if (shdr.sh_type == SHT_STRTAB && !(shdr.sh_flags & SHF_ALLOC))
        {
            strTab = new char[shdr.sh_size];
            fseek(f, shdr.sh_offset, SEEK_SET);
            fread(strTab, 1, shdr.sh_size, f);
            break;
        }

    assert(strTab);
    
    /* iter through sections */
    for (auto& shdr : shdrs)
    {
        switch (shdr.sh_type)
        {
        case SHT_NOBITS:
            assert(!bssShdr);
            bssShdr = &shdr;
            break;
        case SHT_DYNSYM:
            assert(!dynSymShdr);
            dynSymShdr = &shdr;
            break;
        case SHT_STRTAB:
            if (shdr.sh_flags == SHF_ALLOC)
            {
                assert(!dynStrShdr);
                dynStrShdr = &shdr;
            }
            break;
        case SHT_PROGBITS:
            if (!strcmp(strTab + shdr.sh_name, ".sdk_packages"))
            {
                assert(!apiInfoShdr);
                apiInfoShdr = &shdr;
            }
        case SHT_NOTE:
            if (!noteFound)
            {
                Elf64_Nhdr nHdr;
                fseek(f, shdr.sh_offset, SEEK_SET);
                fread(&nHdr, 1, sizeof(Elf64_Nhdr), f);

                char* noteBuff = new char[nHdr.n_namesz + nHdr.n_descsz + 1];
                
                if (!strncmp(noteBuff, "GNU", nHdr.n_namesz))
                {
                    memcpy(m_Header.buildID.data, noteBuff + nHdr.n_namesz, std::min(nHdr.n_descsz, (u32)sizeof(m_Header.buildID)));
                    noteFound = true;
                }
                
                delete[] noteBuff;
            }
        };
    }

    if (bssShdr)
        m_Header.bssSize = bssShdr->sh_size;
    if (dynStrShdr)
    {
        m_Header.dynStr.off = dynStrShdr->sh_addr - m_Header.rodata.addr;
        m_Header.dynStr.size = dynStrShdr->sh_size;
    }
    if (dynSymShdr)
    {
        m_Header.dynSym.off = dynSymShdr->sh_addr - m_Header.rodata.addr;
        m_Header.dynSym.size = dynSymShdr->sh_size;
    }
    if (apiInfoShdr)
    {
        m_Header.apiInfo.off = apiInfoShdr->sh_addr - m_Header.rodata.addr;
        m_Header.apiInfo.size = apiInfoShdr->sh_size;
    }

    
    fclose(f);
    if (strTab)
        delete[] strTab;
}