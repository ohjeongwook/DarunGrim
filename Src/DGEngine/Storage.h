#pragma once
#include<iostream>
#include <unordered_set>

using namespace std;
using namespace stdext;

#include "Common.h"
#include "Log.h"
#include "MatchResults.h"
using namespace std;

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

    virtual void ReadBasicBlockInfo(int fileID, char *conditionStr, AnalysisInfo *analysisInfo)
    {
    }

    virtual multimap <va_t, PMapInfo> *ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false)
    {
        return NULL;
    }

    virtual MatchMapList *ReadMatchMap(int sourceID, int targetID, int index, va_t address, bool erase)
    {
        return NULL;
    }

    virtual MatchResults* ReadMatchResults(int sourceID, int targetID)
    {
        return NULL;
    }

    virtual list<BLOCK> ReadFunctionMemberAddresses(int fileID, va_t function_address)
    {
        list<BLOCK> ret;
        return ret;
    }

    virtual FunctionMatchInfoList QueryFunctionMatches(const char *query, int sourceID, int targetID)
    {
        FunctionMatchInfoList ret;
        return ret;
    }

    virtual FileList ReadFileList()
    {
        FileList ret;
        return ret;
    }

    virtual void InsertMatchMap(int sourceFileID, int targetFileID, va_t sourceAddress, va_t targetAddress, int matchType, int matchRate)
    {
    }

    virtual char *GetOriginalFilePath(int fileID)
    {
        return NULL;
    }

    virtual void DeleteMatchInfo(int fileID, va_t functionAddress)
    {
    }

    virtual void DeleteMatches(int srcFileID, int dstFileID)
    {
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

    virtual void AddFileInfo(char *fileType, const char *dbName, int fileID, va_t functionAddress)
    {
    }

    virtual void AddFunctionMatchInfo(int srcFileID, int targetFileID, FunctionMatchInfo& functionMatchInfo)
    {
    }
};
