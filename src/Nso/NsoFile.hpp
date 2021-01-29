#pragma once
#include <cstddef>
#include <stdexcept>
#include "../Utils.hpp"
#include "elf64.h"
#include "dwarf.h"

#define ALIGN_MEM(addr) (((addr) + 0xFFF) & ~0xFFF) 
#define ALIGN4(addr) (((addr) + 3) & ~3)
#define ALIGN8(addr) (((addr) + 7) & ~7)
#define ALIGN16(addr) (((addr) + 0xF) & ~0xF)

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
        /* 0x00 */ u32 off;
        /* 0x04 */ u32 size;
    }; // size = 0x08
    
    struct SegmentHeader
    {
        /* 0x00 */ u32 off;
        /* 0x04 */ u32 addr;
        /* 0x08 */ u32 size;
    }; // size = 0x0C
    
    struct SegmentHash : Id<0x20>
    {
        bool isValid(void* mem, SegmentHeader& hdr);
        void update(void* mem, SegmentHeader& hdr);
        std::string toString(void* mem, SegmentHeader& hdr) { return Id<0x20>::toString() + (isValid(mem, hdr) ? " : VALID" : " : INVALID"); };
    };

    struct Mod0
    {
        /* 0x00 */ FileMagic<STR_TO_U32('M', 'O', 'D', '0')> magic;
        /* 0x04 */ s32 dynOff;
        /* 0x08 */ s32 bssStartOff;
        /* 0x0C */ s32 bssEndOff;
        /* 0x10 */ s32 ehFrameHdrStartOff;
        /* 0x14 */ s32 ehFrameHdrEndOff;
        /* 0x18 */ s32 modObjectOff;
    };
    CHECK_SIZE(Mod0, 0x1C);
    
    struct Header
    {
        /* 0x00 */ FileMagic<STR_TO_U32('N', 'S', 'O', '0')> magic;
        /* 0x04 */ u32 version;
        /* 0x08 */ u32 reserved;
        /* 0x0C */ u32 textCompressed : 1;
        /* 0x0C */ u32 rodataCompressed : 1;
        /* 0x0C */ u32 dataCompressed : 1;
        /* 0x0C */ u32 textHashCheck : 1;
        /* 0x0C */ u32 rodataHashCheck : 1;
        /* 0x0C */ u32 dataHashCheck : 1;
        /* 0x10 */ SegmentHeader text;
        /* 0x1C */ u32 moduleNameOff;
        /* 0x20 */ SegmentHeader rodata;
        /* 0x2C */ u32 moduleNameSize;
        /* 0x30 */ SegmentHeader data;
        /* 0x3C */ u32 bssSize;
        /* 0x40 */ Id<0x20> buildID;
        /* 0x60 */ u32 textEncSize;
        /* 0x64 */ u32 rodataEncSize;
        /* 0x68 */ u32 dataEncSize;
        /* 0x6C */ u8 reserved2[0x1C];
        /* 0x88 */ SegmentHeaderRelative apiInfo;
        /* 0x90 */ SegmentHeaderRelative dynStr;
        /* 0x98 */ SegmentHeaderRelative dynSym;
        /* 0xA0 */ SegmentHash textHash;
        /* 0xC0 */ SegmentHash rodataHash;
        /* 0xE0 */ SegmentHash dataHash;
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
    
private:
    NsoFile();
public:
    ~NsoFile();

public:
    static NsoFile fromNSO(std::string path);
    static NsoFile fromELF(std::string path);

    void printInfo();
    std::string getModuleName();
    std::vector<std::string> getLibraries();
    void writeDecompressed(std::string path);
    void writeCompressed(std::string path);
    void writeELF(std::string path);

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
    void loadELF(std::string path);
    void loadNSO(std::string path);
    void analyze();
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