#pragma once
#include "Utils.hpp"
#include <cstddef>
#include "elf.h"
#include "dwarf.h"
#include <stdexcept>

#define ALIGN_MEM(addr) (((addr) + 0xFFF) & ~0xFFF) 
#define ALIGN4(addr) (((addr) + 3) & ~3)
#define ALIGN8(addr) (((addr) + 7) & ~7)
#define ALIGN16(addr) (((addr) + 0xF) & ~0xF)

class ElfFile;

class NsoFile
{
public:
    struct ModuleName
    {
        u32 reserved;
        u32 size;
        char name[];
    };

    template<int N>
    struct Id
    {
        u8 data[N];
        std::string toString() { return Utils::hexToStr(data, sizeof(data)); }
    };
    
    struct GnuBuildId
    {
        FileMagic<STR_TO_U32('G', 'N', 'U', '\0')> magic;
        Id<0x10> id;
    };
    struct SegmentHeaderRelative // relative to .rodata
    {
        u32 off;
        u32 size;
    };
    
    struct SegmentHeader
    {
        u32 off;
        u32 addr;
        u32 size;
    };
    
    struct SegmentHash : Id<0x20>
    {
        bool isValid(void* mem, SegmentHeader& hdr);
        void update(void* mem, SegmentHeader& hdr);
        std::string toString(void* mem, SegmentHeader& hdr) { return Id<0x20>::toString() + (isValid(mem, hdr) ? " : VALID" : " : INVALID"); };
    };

    struct Mod0
    {
        FileMagic<STR_TO_U32('M', 'O', 'D', '0')> magic;
        s32 dynOff;
        s32 bssStartOff;
        s32 bssEndOff;
        s32 ehFrameHdrStartOff;
        s32 ehFrameHdrEndOff;
        s32 modObjectOff;
    };
    CHECK_SIZE(Mod0, 0x1C);
    
    struct Header
    {
        FileMagic<STR_TO_U32('N', 'S', 'O', '0')> magic;
        u32 version;
        u32 reserved;
        u32 textCompressed : 1;
        u32 rodataCompressed : 1;
        u32 dataCompressed : 1;
        u32 textHashCheck : 1;
        u32 rodataHashCheck : 1;
        u32 dataHashCheck : 1;
        SegmentHeader text;
        u32 moduleNameOff;
        SegmentHeader rodata;
        u32 moduleNameSize;
        SegmentHeader data;
        u32 bssSize;
        Id<0x20> buildID;
        u32 textEncSize;
        u32 rodataEncSize;
        u32 dataEncSize;
        u8 reserved2[0x1C];
        SegmentHeaderRelative apiInfo;
        SegmentHeaderRelative dynStr;
        SegmentHeaderRelative dynSym;
        SegmentHash textHash;
        SegmentHash rodataHash;
        SegmentHash dataHash;
    };
    CHECK_SIZE(Header, 0x100);

    enum class SegmentType
    {
        invalid = -1,
        text,
        data,
        rodata,
        bss,
    };

    class Section
    {
    public:
        size_t m_Addr;
        union
        {
            size_t m_Size;
            size_t m_Align;
        };
        std::string m_Name;

    public:
        // for padding
        Section(size_t addr, size_t alignment) :
            m_Addr(addr),
            m_Align(alignment),
            m_Name("padding")
        {
            bool valid = false;
            for (size_t i = 0; i < sizeof(size_t) * 8; i++)
            {
                if (m_Align == 1 << i)
                {
                    valid = true;
                    break;
                }
            }
            if (!valid)
                throw std::runtime_error("alignment must be a power of 2");
        }
        Section(size_t addr, size_t size, std::string name) : m_Addr(addr), m_Size(size), m_Name(name) {}

        inline bool isPadding() const { return m_Name == "padding"; }
        inline size_t start() const { return m_Addr; }
        inline size_t end() const { return isPadding() ? ((m_Addr + (m_Align-1)) & ~(m_Align-1)) : (m_Addr + m_Size); }
        inline size_t size() const { return m_Size; }
        inline std::string name() const { return m_Name; }
    };
    
public:
    NsoFile(ElfFile* elf);
    NsoFile(std::string path);
    ~NsoFile();

public:
    void printInfo();
    std::string getModuleName();
    std::vector<std::string> getLibraries();
    void writeDecompressed(std::string path);
    void writeCompressed(std::string path);

    inline Elf64_Dyn* getElf64Dyns() const { return (Elf64_Dyn*)((char*)m_Mod0 + m_Mod0->dynOff); }
    inline Elf64_Dyn* getElf64Dyn(u64 tag) const
    {
        auto dyn = getElf64Dyns();
        while (dyn->d_tag != DT_NULL)
        {
            if (dyn->d_tag == tag)
                return dyn;
            dyn++;
        }
        return nullptr;
    }


    template<typename T = void>
    inline T* mem(size_t off = 0) { return reinterpret_cast<T*>(m_Mem.data() + off); }
    template<typename T = void>
    inline T* text(size_t off = 0) { return reinterpret_cast<T*>(m_Mem.data() + m_Header.text.addr + off); }
    template<typename T = void>
    inline T* rodata(size_t off = 0) { return reinterpret_cast<T*>(m_Mem.data() + m_Header.rodata.addr + off); }
    template<typename T = void>
    inline T* data(size_t off = 0) { return reinterpret_cast<T*>(m_Mem.data() + m_Header.data.addr + off); }

    inline u32 getMod0Pointer() { return *mem<u32>(4); }
    Section* getSection(std::string name);
    size_t getAppSectionCount(std::string name);
    SegmentType getSegmentType(size_t addr);

private:
    void processSection(FILE* f, SegmentHeader& hdr, u32 encSize, bool compressed);
    void findElfSections();
    size_t findNoteGnuBuildId();
    size_t getFiniSize(size_t start);
    size_t getPltStart(size_t pltSize);
    void getEhFrame(size_t ehFrameHdrStart, size_t* outStart, size_t* outSize);

public:
    Header m_Header;
    Mod0* m_Mod0;
    Elf64_Nhdr* m_GnuBuildIdNote;
    bool m_IsBaseNso; // first nso to get executed (usually either rtld or a sysmodule)
    std::vector<char> m_Mem;
    std::vector<Section> m_Sections;
};