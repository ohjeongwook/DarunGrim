#pragma once
#include <stdio.h>
#include <string>

#include "StorageDataStructures.h"
#include "DisassemblyStorage.h"

#include "sqlite3.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define FILE_INFO_TABLE "FileInfo"
#define MAP_INFO_TABLE "MapInfo"
#define CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT "CREATE INDEX "MAP_INFO_TABLE"Index ON "MAP_INFO_TABLE" (SrcBlock)"
#define BASIC_BLOCK_TABLE "BasicBlock"

class SQLiteDisassemblyStorage : public DisassemblyStorage
{
private:
    sqlite3 *m_database;
    string m_databaseName;

public:
    SQLiteDisassemblyStorage(const char *DatabaseName = NULL);
    ~SQLiteDisassemblyStorage();

public:
    void Close();
    bool Open(char *DatabaseName);
    const char *GetDatabaseName();
    void CloseDatabase();
    bool ConnectDatabase(const char *DatabaseName);

    int ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...);
    static int display_callback(void *NotUsed, int argc, char **argv, char **azColName);
    static int ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names);
    static int ReadRecordStringCallback(void *arg, int argc, char **argv, char **names);

    static int ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names);
    void ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap);

    char *ReadInstructionHash(int fileID, va_t address);
    char *ReadName(int fileID, va_t address);
    va_t ReadBlockStartAddress(int fileID, va_t address);

    static int ReadBasicBlockDataCallback(void *arg, int argc, char **argv, char **names);
    void ReadBasicBlockInfo(int fileID, char *conditionStr, AnalysisInfo *analysisInfo);

    static int ReadMapInfoCallback(void *arg, int argc, char **argv, char **names);
    multimap <va_t, PMapInfo> *ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false);

    static int ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names);
    list<BLOCK> ReadFunctionMemberAddresses(int fileID, va_t function_address);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);

    char *GetOriginalFilePath(int fileID);

    char *ReadDisasmLine(int fileID, va_t startAddress);

    static int ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names);
    PBasicBlock ReadBasicBlock(int fileID, va_t address);
};
