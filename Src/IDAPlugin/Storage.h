#pragma once
#include<iostream>
#include <unordered_set>
#include "Common.h"
#include "Log.h"

using namespace std;
using namespace stdext;

class Storage
{
public:
    virtual void SetFileInfo(FileInfo *p_file_info)
    {
    }

    virtual int BeginTransaction()
    {
        return 0;
    }

    virtual int EndTransaction()
    {
        return 0;
    }

    virtual void Close()
    {
    }

    virtual int ProcessTLV(BYTE Type, PBYTE Data, DWORD Length)
    {
        return 0;
    }

    virtual void AddBasicBlock(PBasicBlock p_basic_block, int fileID = 0)
    {
    }

    virtual void AddMapInfo(PMapInfo p_map_info, int fileID = 0)
    {
    }

    virtual void ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap)
    {
    }

    virtual char *ReadFingerPrint(int fileID, va_t address)
    {
        return NULL;
    }

    virtual char *ReadName(int fileID, va_t address)
    {
        return NULL;
    }

    virtual va_t ReadBlockStartAddress(int fileID, va_t address)
    {
        return 0;
    }

    virtual multimap <va_t, PMapInfo> *ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false)
    {
        return NULL;
    }

    virtual list<BLOCK> ReadFunctionMemberAddresses(int fileID, va_t function_address)
    {
        list<BLOCK> ret;
        return ret;
    }

    virtual char *GetOriginalFilePath(int fileID)
    {
        return NULL;
    }

    virtual char *ReadDisasmLine(int fileID, va_t startAddress)
    {
        return NULL;
    }

    virtual BasicBlock *ReadBasicBlock(int fileID, va_t address)
    {
        return NULL;
    }

    virtual void UpdateBasicBlock(int fileID, va_t address1, va_t address2)
    {
    }
};
