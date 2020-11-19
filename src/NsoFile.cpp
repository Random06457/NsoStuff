#include <iostream>
#include <cstring>
#include <exception>
#include "lz4.h"
#include "sha256.h"
#include "NsoFile.hpp"
#include "Utils.hpp"
#include <algorithm>


bool NsoFile::SegmentHash::isValid(void* mem, SegmentHeader& hdr)
{
    u8 hash[32];
    sha256_hash(hash, (u8*)mem + hdr.addr, hdr.size);
    return memcmp(hash, data, 32) == 0;
}

void NsoFile::SegmentHash::update(void* mem, SegmentHeader& hdr)
{
    sha256_hash(data, (u8*)mem + hdr.addr, hdr.size);
}

NsoFile::NsoFile(std::string path) :
    m_Header(),
    m_Mod0(nullptr),
    m_GnuBuildIdNote(nullptr),
    m_IsBaseNso(false),
    m_Mem(),
    m_Sections()
{
    FILE* f = fopen(path.c_str(), "rb");
    fread(&m_Header, 1, sizeof(NsoFile::Header), f);

    size_t memSize = ALIGN_MEM(m_Header.data.addr + m_Header.data.size);
    m_Mem.reserve(memSize);
    m_Mem.resize(memSize);

    processSection(f, m_Header.text, m_Header.textEncSize, m_Header.textCompressed);
    processSection(f, m_Header.rodata, m_Header.rodataEncSize, m_Header.rodataCompressed);
    processSection(f, m_Header.data, m_Header.dataEncSize, m_Header.dataCompressed);
    fclose(f);

    // get mod0
    u32 modAddr = getMod0Pointer();
    m_Mod0 = mem<NsoFile::Mod0>(modAddr);
    if (!m_Mod0 || !m_Mod0->magic.isValid())
        throw std::runtime_error("Could not find MOD0");

    m_IsBaseNso = modAddr != 8;

    findElfSections();
}

NsoFile::~NsoFile()
{
}

void NsoFile::processSection(FILE* f, SegmentHeader& hdr, u32 encSize, bool compressed)
{
    fseek(f, hdr.off, SEEK_SET);

    if (compressed)
    {
        char* buff = new char[encSize];
        fread(buff, 1, encSize, f);
        
        LZ4_decompress_fast(buff, mem<char>(hdr.addr), hdr.size);

        delete[] buff;
    }
    else
        fread(mem(hdr.addr), 1, encSize, f);
}

void NsoFile::printInfo()
{
    #define RANGE(off, size) off, off+size, size

    printf("magic: %s\n", m_Header.magic.toString().c_str());
    printf("\n");

    printf("segments:\n");
    printf("%08X-%08X(0x%08X) : .text (%s)\n", RANGE(m_Header.text.addr, m_Header.text.size), m_Header.textHash.toString(m_Mem.data(), m_Header.text).c_str());
    printf("%08X-%08X(0x%08X) : .rodata (%s)\n", RANGE(m_Header.rodata.addr, m_Header.rodata.size), m_Header.rodataHash.toString(m_Mem.data(), m_Header.rodata).c_str());
    printf("%08X-%08X(0x%08X) : .data (%s)\n", RANGE(m_Header.data.addr, m_Header.data.size), m_Header.dataHash.toString(m_Mem.data(), m_Header.data).c_str());
    
    u32 bssStart = m_Header.data.addr + m_Header.data.size;
    printf("%08X-%08X(0x%08X) : .bss\n", bssStart, bssStart + m_Header.bssSize, m_Header.bssSize);
    printf("\n");

    printf("module: \"%s\"\n", getModuleName().c_str());
    printf("\n");
    
    std::string buildId = m_Header.buildID.toString();
    buildId.resize(m_GnuBuildIdNote->n_descsz*2);
    printf("GNU Build ID: %s\n", buildId.c_str());
    printf("\n");

    printf("Libraries:\n");
    auto libs = getLibraries();
    for (auto lib : libs)
        printf("%s\n", lib.c_str());
    printf("\n");

    printf("MOD0:\n");
    printf("magic: %s\n", m_Mod0->magic.toString().c_str());
    printf("Elf Dynamic Information:\n");
    auto dyn = getElf64Dyns();
    while (dyn->d_tag != DT_NULL)
    {
        printf("\td_tag=0x%llX; d_un=0x%llX\n", dyn->d_tag, dyn->d_un);
        dyn++;
    }
    printf("\n");

    
    /*
    printf("ELF64 Symbols:\n");
    auto symTab = rodata<Elf64_Sym>(m_Header.dynSym.off);
    for (size_t i = 0; i < m_Header.dynSym.size / sizeof(Elf64_Sym); i++)
    {

        if (
            (ELF64_ST_TYPE(symTab[i].st_info) != STT_FUNC && ELF64_ST_TYPE(symTab[i].st_info) != STT_OBJECT)/_* && ELF64_ST_TYPE(symTab[i].st_info) != STT_NOTYPE)*_/
            //symTab[i].st_other != 0 // 3 : _init/_fini
        )
        printf("\tbind=%d; type=%d; other=%d; shndx=%d; value=0x%08X; size=0x%X; name=%s\n",
            ELF64_ST_BIND(symTab[i].st_info), ELF64_ST_TYPE(symTab[i].st_info), symTab[i].st_other, symTab[i].st_shndx,
            symTab[i].st_value, symTab[i].st_size, rodata<char>(m_Header.dynStr.off + symTab[i].st_name)
            );
    }
    printf("\n");
    */
    

    printf("ELF Sections:\n");
    for (auto section : m_Sections)
    {
        if (section.isPadding())
            printf("\t. = ALIGN(0x%lX)\n", section.m_Align);
        else 
            printf("\t%08lX-%08lX(%08lX) : %s\n", RANGE(section.start(), section.size()), section.name().c_str());
    }
    printf("\n");
    
    
    
    
}

std::string NsoFile::getModuleName()
{
    ModuleName* module = rodata<ModuleName>();
    return std::string(module->name, module->size);
}

std::vector<std::string> NsoFile::getLibraries()
{
    std::vector<std::string> libs;

    auto section = getSection(".sdk_packages");
    if (!section)
        return libs;
    char* ptr = mem<char>(section->start());

    while (ptr < mem<char>(section->end()))
    {
        size_t len = strlen(ptr);
        libs.push_back(std::string(ptr));
        ptr += len+1;
    }

    return libs;
    
}

void NsoFile::writeDecompressed(std::string path)
{
    m_Header.textCompressed = false;
    m_Header.rodataCompressed = false;
    m_Header.dataCompressed = false;

    // update hashes
    m_Header.textHash.update(m_Mem.data(), m_Header.text);
    m_Header.rodataHash.update(m_Mem.data(), m_Header.rodata);
    m_Header.dataHash.update(m_Mem.data(), m_Header.data);

    // update module name
    char moduleName[1];
    u32 off = sizeof(NsoFile::Header);
    m_Header.moduleNameOff = sizeof(NsoFile::Header);
    m_Header.moduleNameSize = sizeof(moduleName);
    off += sizeof(moduleName);

    // update segments off / size
    m_Header.text.off = off;
    m_Header.textEncSize = m_Header.text.size;
    off += m_Header.text.size;

    m_Header.rodata.off = off;
    m_Header.rodataEncSize = m_Header.rodata.size;
    off += m_Header.rodata.size;

    m_Header.data.off = off;
    m_Header.dataEncSize = m_Header.data.size;
    off += m_Header.data.size;

    printf("writing \"%s\"...\n", path.c_str());

    // write file
    FILE* f = fopen(path.c_str(), "wb");
    fwrite(&m_Header, 1, sizeof(NsoFile::Header), f);
    fwrite(moduleName, 1, sizeof(moduleName), f);
    fwrite(text(), 1, m_Header.text.size, f);
    fwrite(rodata(), 1, m_Header.rodata.size, f);
    fwrite(data(), 1, m_Header.data.size, f);
    fclose(f);

    printf("done!\n");
}
void NsoFile::writeCompressed(std::string path)
{
    m_Header.textCompressed = true;
    m_Header.rodataCompressed = true;
    m_Header.dataCompressed = true;
    
    // update hashes
    m_Header.textHash.update(m_Mem.data(), m_Header.text);
    m_Header.rodataHash.update(m_Mem.data(), m_Header.rodata);
    m_Header.dataHash.update(m_Mem.data(), m_Header.data);

    // update module name
    char moduleName[1];
    u32 off = sizeof(NsoFile::Header);
    m_Header.moduleNameOff = sizeof(NsoFile::Header);
    m_Header.moduleNameSize = sizeof(moduleName);
    off += sizeof(moduleName);

    int buffSize = 0x100000;
    char* buff = new char[buffSize];

    // write file and update off / encSize
    printf("writing \"%s\"...\n", path.c_str());

    FILE* f = fopen(path.c_str(), "wb");
    // temp
    fwrite(&m_Header, 1, sizeof(NsoFile::Header), f);
    fwrite(moduleName, 1, sizeof(moduleName), f);

    m_Header.text.off = off;
    s32 encSize = LZ4_compress_default(text<char>(), buff, m_Header.text.size, buffSize);
    m_Header.textEncSize = encSize;
    off += encSize;
    fwrite(buff, 1, encSize, f);
    
    m_Header.rodata.off = off;
    encSize = LZ4_compress_default(rodata<char>(), buff, m_Header.rodata.size, buffSize);
    m_Header.rodataEncSize = encSize;
    off += encSize;
    fwrite(buff, 1, encSize, f);
    
    m_Header.data.off = off;
    encSize = LZ4_compress_default(data<char>(), buff, m_Header.data.size, buffSize);
    m_Header.dataEncSize = encSize;
    off += encSize;
    fwrite(buff, 1, encSize, f);

    // rewrite header
    fseek(f, 0, SEEK_SET);
    fwrite(&m_Header, 1, sizeof(NsoFile::Header), f);
    fclose(f);

    printf("done!\n");
}

size_t NsoFile::getFiniSize(size_t start)
{
    for (size_t addr = start; addr < m_Header.text.addr + m_Header.text.size; addr += 4)
        if ((*text<u32>(addr) & 0xff000000) == 0x14000000) // b off
            return addr + 4 - start;
    
    throw std::runtime_error("Could not get .fini size");
}

size_t NsoFile::getPltStart(size_t pltSize)
{
    size_t textStart = m_Header.text.addr;
    size_t textEnd = textStart + m_Header.text.size;
    pltSize -= 0x20;

    for (ssize_t start = textEnd - pltSize; start >= textStart; start -= 4)
    {
        bool match = true;
        for (size_t addr = start; addr < start + pltSize; addr += 0x10)
        {
            u32* ins = text<u32>(addr);
            
            if (((ins[0] & 0x9f00001f) != 0x90000010) ||    // adrp x16, page
                ((ins[1] & 0xffe003ff) != 0xf9400211) ||    // ldr x17, [x16, off] 
                (ins[2] == 0xD61F0220)                      // br x17
            )
            {
                match = false;
                break;
            }
        }

        if (match)
            return start - 0x20;
    }
    

    throw std::runtime_error("Could not get .plt size");
}

size_t NsoFile::findNoteGnuBuildId()
{
    for (size_t i = ALIGN4(m_Header.data.addr - 0x14); i >= m_Header.rodata.addr; i -= 4)
        if (!memcmp(mem(i), "\3\0\0\0GNU\0", 8))
            return i - sizeof(Elf64_Nhdr) + 4;

    throw std::runtime_error("Could not find GNU build id");
}


NsoFile::SegmentType NsoFile::getSegmentType(size_t addr)
{
    if (addr >= m_Header.text.addr && addr < m_Header.text.addr + m_Header.text.size)
        return SegmentType::text;
    if (addr >= m_Header.rodata.addr && addr < m_Header.rodata.addr + m_Header.rodata.size)
        return SegmentType::rodata;
    if (addr >= m_Header.data.addr && addr < m_Header.data.addr + m_Header.data.size)
        return SegmentType::data;
    size_t bssStart = m_Header.data.addr + m_Header.data.size;
    if (addr >= bssStart && addr <= bssStart + m_Header.bssSize)
        return SegmentType::bss;
    return SegmentType::invalid;
}

void NsoFile::getEhFrame(size_t ehFrameHdrStart, size_t* outStart, size_t* outSize)
{
    auto ehFrameHdr = mem<EhFrameHdr>(ehFrameHdrStart);

    #define DWARF_DECODE(type, enc, data) ehFrameHdr->decode<type>(enc, &data, reinterpret_cast<u8*>(&data) - mem<u8>(), ehFrameHdrStart);
    
    u32 fdeCount = DWARF_DECODE(u32, ehFrameHdr->fde_count_enc, ehFrameHdr->fde_count);
    *outStart = DWARF_DECODE(size_t, ehFrameHdr->eh_frame_ptr_enc, ehFrameHdr->eh_frame_ptr);

    u32 lastFde = 0;
    for (size_t i = 0; i < fdeCount; i++)
    {
        u32 funcAddr = DWARF_DECODE(u32, ehFrameHdr->table_enc, ehFrameHdr->entries[i].funcAddr);
        u32 fdeAddr = DWARF_DECODE(u32, ehFrameHdr->table_enc, ehFrameHdr->entries[i].fdeAddr);

        if (fdeAddr > lastFde)
            lastFde = fdeAddr;
    }
    EhFrameEntry* fde = mem<EhFrameEntry>(lastFde);
    *outSize = (lastFde + 4 + fde->length) - *outStart;
}

void NsoFile::findElfSections()
{
    auto dynInit = getElf64Dyn(DT_INIT);
    auto dynFini = getElf64Dyn(DT_FINI);
    auto dynRela = getElf64Dyn(DT_RELA);
    auto dynRelaSz = getElf64Dyn(DT_RELASZ);
    auto dynJmpRel = getElf64Dyn(DT_JMPREL);
    auto dynPltRelSz = getElf64Dyn(DT_PLTRELSZ);
    auto dynHash = getElf64Dyn(DT_HASH);
    auto dynGnuHash = getElf64Dyn(DT_GNU_HASH);
    auto dynPltGotStart = getElf64Dyn(DT_PLTGOT);
    auto dynInitArray = getElf64Dyn(DT_INIT_ARRAY);
    auto dynInitArraySz = getElf64Dyn(DT_INIT_ARRAYSZ);
    auto dynFiniArray = getElf64Dyn(DT_FINI_ARRAY);
    auto dynFiniArraySz = getElf64Dyn(DT_FINI_ARRAYSZ);

    size_t dynSymAddr = m_Header.rodata.addr + m_Header.dynSym.off;
    size_t dynSymSize = m_Header.dynSym.size;
    size_t dynStrAddr = m_Header.rodata.addr + m_Header.dynStr.off;
    size_t dynStrSize = m_Header.dynStr.size;
    size_t ehFrameHdrStart = getMod0Pointer() + m_Mod0->ehFrameHdrStartOff;
    size_t ehFrameHdrSize = (getMod0Pointer() + m_Mod0->ehFrameHdrEndOff) - ehFrameHdrStart;
    size_t dynStart = getMod0Pointer() + m_Mod0->dynOff;
    size_t bssStart = m_Header.data.addr + m_Header.data.size;

    // todo: check pointers

    // .text special sections

    m_Sections.push_back(Section(dynInit->d_un, dynFini->d_un - dynInit->d_un, ".init"));
    m_Sections.push_back(Section(dynFini->d_un, getFiniSize(dynFini->d_un), ".fini"));
    
    if (m_IsBaseNso)
        m_Sections.push_back(Section(m_Header.text.addr, dynInit->d_un - m_Header.text.addr, ".crt0"));
    else
        m_Sections.push_back(Section(m_Header.text.addr, sizeof(Mod0) + 8, ".mod0"));

    size_t pltSize = (2 + dynPltRelSz->d_un/sizeof(Elf64_Rela)) * 0x10;
    m_Sections.push_back(Section(getPltStart(pltSize), pltSize, ".plt"));

    // .rodata special sections
    
    size_t size = sizeof(NsoFile::ModuleName) + rodata<NsoFile::ModuleName>()->size;
    m_Sections.push_back(Section(m_Header.rodata.addr, size, ".module_name"));
    // align 8
    m_Sections.push_back(Section(m_Header.rodata.addr + size, 8));

    m_Sections.push_back(Section(dynRela->d_un, dynRelaSz->d_un, ".rela.dyn"));
    m_Sections.push_back(Section(dynJmpRel->d_un, dynPltRelSz->d_un, ".rela.plt"));

    auto hash = mem<Elf64_Hash>(dynHash->d_un);
    size = sizeof(Elf64_Hash) + (hash->nbuckets + hash->nchains) * sizeof(u32);
    m_Sections.push_back(Section(dynHash->d_un, size, ".hash"));
    // align 8
    m_Sections.push_back(Section(dynHash->d_un + size, 8));

    auto gnuHash = mem<Elf64_GnuHash>(dynGnuHash->d_un);
    // the size is sometimes invalid (sometimes there are 4 bytes at the end)
    /*
    u32 dynSymCount = dynSymSize / sizeof(Elf64_Sym);
    size = sizeof(Elf64_GnuHash) +
        gnuHash->maskwords * sizeof(u64) +
        gnuHash->nbuckets * sizeof(u32) +
        (dynSymCount - gnuHash->symndx) * sizeof(u32);
    */
    //m_Sections.push_back(Section(dynGnuHash->d_un, size, ".gnu.hash"));
    m_Sections.push_back(Section(dynGnuHash->d_un, dynSymAddr - dynGnuHash->d_un, ".gnu.hash"));

    m_Sections.push_back(Section(dynSymAddr, dynSymSize, ".dynsym"));
    m_Sections.push_back(Section(dynStrAddr, dynStrSize, ".dynstr"));

    m_Sections.push_back(Section(ehFrameHdrStart, ehFrameHdrSize, ".eh_frame_hdr"));
    // align 16
    m_Sections.push_back(Section(ehFrameHdrStart + ehFrameHdrSize, 16));

    size_t ehFrameStart = 0;
    getEhFrame(ehFrameHdrStart, &ehFrameStart, &size);
    m_Sections.push_back(Section(ehFrameStart, size, ".eh_frame"));
    // align 16
    m_Sections.push_back(Section(ehFrameStart + size, 16));
    
    // .rodata misc
    // misc stuff starting here : mod0, sdk packages / .note.gnu.build-id
    size_t curMiscAddr = ALIGN16(ehFrameStart + size);

    // it seems like there are always 4 bytes here??
    m_Sections.push_back(Section(curMiscAddr, 4, ".misc_start"));
    curMiscAddr += 4;

    // for base nsos, this is at .text start
    if (m_IsBaseNso)
    {
        size_t modStart = getMod0Pointer() - 8;
        m_Sections.push_back(Section(modStart, sizeof(Mod0) + 8, ".mod0"));
        curMiscAddr += sizeof(Mod0) + 8;
    }

    size_t noteAddr = findNoteGnuBuildId();
    m_GnuBuildIdNote = mem<Elf64_Nhdr>(noteAddr);
    size_t noteSize = sizeof(Elf64_Nhdr) + m_GnuBuildIdNote->n_namesz + m_GnuBuildIdNote->n_descsz;
    m_Sections.push_back(Section(noteAddr, noteSize, ".note.gnu.build-id"));

    // .sdk_packages after .note.gnu.build-id
    if (noteAddr == curMiscAddr)
    {
        size = m_Header.rodata.addr + m_Header.rodata.size - (noteAddr + noteSize);
        if (size > 0)
            m_Sections.push_back(Section(noteAddr + noteSize, size, ".sdk_packages"));
    }
    // .sdk_packages before .note.gnu.build-id
    else 
    {
        size = noteAddr - curMiscAddr;
        char* ptr = mem<char>(curMiscAddr+size-1);
        while (ptr-1 >= mem<char>(curMiscAddr) && ptr[0] == 0 && ptr[-1] == 0) 
        {
            ptr--;
            size--;
        }
        
        if (size > 1)
            m_Sections.push_back(Section(curMiscAddr, size, ".sdk_packages"));
        // align 4
        m_Sections.push_back(Section(curMiscAddr + size, 4));
    }



    // .data special sections

    /*
    Elf64_Dyn* dyn = mem<Elf64_Dyn>(dynStart);
    size = sizeof(Elf64_Dyn);
    while ((dyn++)->d_tag != DT_NULL)
        size += sizeof(Elf64_Dyn);
    */

    // .dynamic is bigger??
    size = dynPltGotStart->d_un - dynStart;
    m_Sections.push_back(Section(dynStart, size, ".dynamic"));

    size = 0x18 + (dynPltRelSz->d_un/sizeof(Elf64_Rela)*8);
    m_Sections.push_back(Section(dynPltGotStart->d_un, size, ".got.plt"));
    

    size_t gotEnd = 0;
    if (dynInitArray)
        gotEnd = dynInitArray->d_un;
    else if (dynFiniArray)
        gotEnd = dynFiniArray->d_un;
    else
        gotEnd = bssStart;
    
    size_t gotStart = dynPltGotStart->d_un + size;
    m_Sections.push_back(Section(gotStart, gotEnd - gotStart, ".got"));

    
    if (dynInitArray && dynInitArraySz)
        m_Sections.push_back(Section(dynInitArray->d_un, dynInitArraySz->d_un, ".init_array"));
        
    if (dynFiniArray && dynFiniArraySz)
        m_Sections.push_back(Section(dynFiniArray->d_un, dynFiniArraySz->d_un, ".fini_array"));


    m_Sections.push_back(Section(bssStart, m_Header.bssSize, ".bss"));
    
    // add segment alignments
    m_Sections.push_back(Section(m_Header.text.addr + m_Header.text.size, 0x1000));
    m_Sections.push_back(Section(m_Header.rodata.addr + m_Header.rodata.size, 0x1000));


    // sort sections
    std::sort(m_Sections.begin(), m_Sections.end(),
        [](const Section& a, const Section& b) -> bool {
            return (a.start() < b.start()) || (a.start() == a.end() && a.end() == b.start());
        }
    );


    // fill sections

    size_t textCount = 0, dataCount = 0, rodataCount = 0;

    size_t oldSize = m_Sections.size();
    for (size_t i = 1; i < oldSize; i++)
    {
        size_t curAddr = m_Sections[i].start();
        size_t lastEnd = m_Sections[i-1].end();

        SegmentType curSegment = getSegmentType(curAddr);
        SegmentType lastSegment = getSegmentType(lastEnd-1);

        if (curAddr > lastEnd)
        {
            
            std::string name;

            switch (curSegment)
            {
            case SegmentType::text:
                name = ".text" + (textCount++ == 0 ? "" : std::to_string(textCount));// + " /* App Data */ ";
                break;
            case SegmentType::rodata:
                name = ".rodata" + (rodataCount++ == 0 ? "" : std::to_string(rodataCount));// + " /* App Data */ ";
                break;
            case SegmentType::data:
                name = ".data" + (dataCount++ == 0 ? "" : std::to_string(dataCount));// + " /* App Data */ ";
                break;
            
            default:
                throw std::runtime_error("Invalid Segment");
            }

            m_Sections.push_back(Section(lastEnd, curAddr - lastEnd, name));
            
            // sort sections
            std::sort(m_Sections.begin(), m_Sections.end(),
                [](const Section& a, const Section& b) -> bool {
                    return (a.start() < b.start()) || (a.start() == a.end() && a.end() == b.start());
                }
            );
        }
        else if (curAddr < lastEnd)
            m_Sections[i-1].m_Name += " (OVERLAPPING)";
            //throw std::runtime_error("Overlapping Sections");
    }
}

NsoFile::Section* NsoFile::getSection(std::string name)
{
    for (size_t i = 0; i < m_Sections.size(); i++)
    {
        if (m_Sections[i].name() == name)
            return &m_Sections[i];
    }

    return nullptr;
}

size_t NsoFile::getAppSectionCount(std::string name)
{
    size_t count = 0;

    for (size_t i = 0; i < m_Sections.size(); i++)
    {
        if (m_Sections[i].name() == name + ((count == 0) ? "" : std::to_string(count)));
            count++;
    }

    return count;
}