#pragma once

#include "Types.h"
#include <cstring>
#include <stdexcept>

#define DW_EH_PE_omit       0xFF
#define DW_EH_PE_uleb128    0x01
#define DW_EH_PE_udata2     0x02
#define DW_EH_PE_udata4     0x03
#define DW_EH_PE_udata8     0x04
#define DW_EH_PE_sleb128    0x09
#define DW_EH_PE_sdata2     0x0A
#define DW_EH_PE_sdata4     0x0B
#define DW_EH_PE_sdata8     0x0C

#define DW_EH_PE_absptr     0x00
#define DW_EH_PE_pcrel      0x01
#define DW_EH_PE_datarel    0x03


template<typename T>
T decodeULEB128(void* data, size_t* outSize = nullptr)
{
    if (outSize) *outSize = 0;

    u8* ptr = reinterpret_cast<u8*>(data);
    T ret;
    size_t shift = 0;
    while (*ptr >> 7)
    {
        if (outSize) *outSize++;

        ret |= (*ptr & 0x7F) << shift;
        shift += 7;
    }
    return ret;
}
template<typename T>
T decodeSLEB128(void* data, size_t* outSize = nullptr)
{
    if (outSize) *outSize = 0;

    u8* ptr = reinterpret_cast<u8*>(data);
    T ret;
    size_t shift = 0;
    while (*ptr >> 7)
    {
        if (outSize) *outSize++;

        ret |= (*ptr & 0x7F) << shift;
        shift += 7;
    }

    if (ret >> shift)
        ret |= (~0ll << shift);
    return ret;
}


struct EhFrameEntry
{
    u32 length;
    u32 id;
};

struct DwarfCie : EhFrameEntry
{
    u8 version;
    size_t codeAlignFactor;
    ssize_t dataAlignFactor;
    size_t returnAddr;

    // 'z'
    bool hasAugmDataLength;
    size_t augmDataLength;

    // 'R'
    bool hasFdeEncoding;
    u8 fdeEncoding;

    // 'S'
    bool isStackFrame;

    // 'P'
    bool hasPersonality;
    u8 personalityEnc;
    size_t personalityFunc;

    DwarfCie(void* data)
    {
        u8* ptr = reinterpret_cast<u8*>(data);
        length = *reinterpret_cast<u32*>(ptr); ptr += 4;
        id = *ptr++;
        version = *ptr++;
        char* augmStr = reinterpret_cast<char*>(ptr);
        ptr += strlen(augmStr)+1;

        size_t size = 0;
        if (augmStr[0] == 'z') {
            augmStr++;
            hasAugmDataLength = true;
            augmDataLength = decodeULEB128<size_t>(ptr, &size);
            ptr += size;
        }

        hasAugmDataLength = hasFdeEncoding = isStackFrame = hasPersonality = false;
        while (*augmStr)
        {
            switch (*augmStr++)
            {
            case 'R':
                hasFdeEncoding = true;
                fdeEncoding = *ptr++;
                break;
            case 'S':
                isStackFrame = true;
                break;
            case 'P':
                hasPersonality = true;
                personalityEnc = *ptr++;
                personalityFunc = decodeULEB128<size_t>(ptr, &size);
                ptr += size;
                break;
            
            default:
                throw std::runtime_error("Invalid Augmentation String");
            }
        }
        
    }
};

struct EhFrameHdrTableEntry
{
    u32 funcAddr;
    u32 fdeAddr;
};


struct EhFrameHdr
{
    u8 version;
    u8 eh_frame_ptr_enc;
    u8 fde_count_enc;
    u8 table_enc;
    u32 eh_frame_ptr;
    u32 fde_count;
    EhFrameHdrTableEntry entries[];

    template<typename T>
    T decode(u8 enc, void* data, size_t pc, size_t ehFrameHdr)
    {
        if (enc == 0xFF)
            return 0;

        //void* data = nso->mem<void>(pc);

        u8 format = enc & 0xF;
        u8 mod = enc >> 4;

        T ret = 0; 
        switch (format)
        {
        case DW_EH_PE_uleb128:
            ret = decodeULEB128<T>(data);
            break;
        case DW_EH_PE_sleb128:
            ret = decodeSLEB128<T>(data);
            break;
        case DW_EH_PE_udata2:
            ret = *reinterpret_cast<u16*>(data);
            break;
        case DW_EH_PE_sdata2:
            ret = *reinterpret_cast<s16*>(data);
            break;
        case DW_EH_PE_udata4:
            ret = *reinterpret_cast<u32*>(data);
            break;
        case DW_EH_PE_sdata4:
            ret = *reinterpret_cast<s32*>(data);
            break;
        case DW_EH_PE_udata8:
            ret = *reinterpret_cast<u64*>(data);
            break;
        case DW_EH_PE_sdata8:
            ret = *reinterpret_cast<s64*>(data);
            break;
        default:
            throw std::runtime_error("Invalid DWARF value format");
        }

        switch (mod)
        {
        case DW_EH_PE_absptr: return ret;
        case DW_EH_PE_pcrel: return pc + ret;
        case DW_EH_PE_datarel: return ehFrameHdr + ret;

        default:
            throw std::runtime_error("Invalid DWARF value modification");
        }
    }
};


