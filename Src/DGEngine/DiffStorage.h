#pragma once
#include<iostream>
#include <unordered_set>

using namespace std;
using namespace stdext;

#include "Common.h"
#include "Log.h"
#include "MatchResults.h"
using namespace std;

class DiffStorage
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

    virtual MatchMapList *ReadMatchMap(int sourceID, int targetID, int index, va_t address, bool erase)
    {
        return NULL;
    }

    virtual MatchResults* ReadMatchResults(int sourceID, int targetID)
    {
        return NULL;
    }

    virtual list<AddressRange> ReadFunctionMemberAddresses(int fileID, va_t function_address)
    {
        list<AddressRange> ret;
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

    virtual string GetOriginalFilePath(int fileID)
    {
        return NULL;
    }

    virtual void DeleteMatchInfo(int fileID, va_t functionAddress)
    {
    }

    virtual void DeleteMatches(int srcFileID, int dstFileID)
    {
    }

    virtual void AddFileInfo(char *fileType, const char *dbName, int fileID, va_t functionAddress)
    {
    }

    virtual void AddFunctionMatchInfo(int srcFileID, int targetFileID, FunctionMatchInfo& functionMatchInfo)
    {
    }
};
