#pragma once
#include <stdio.h>
#include <string>

#include "Common.h"
#include "DiffStorage.h"

#include "sqlite3.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define MATCH_MAP_TABLE "MatchMap"
#define CREATE_MATCH_MAP_TABLE_STATEMENT "CREATE TABLE " MATCH_MAP_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            TheSourceFileID INTEGER, \n\
            TheTargetFileID INTEGER, \n\
            SourceAddress INTEGER, \n\
            TargetAddress INTEGER, \n\
            MatchType INTEGER, \n\
            Type INTEGER, \n\
            SubType INTEGER, \n\
            Status INTEGER, \n\
            MatchRate INTEGER, \n\
            UnpatchedParentAddress INTEGER, \n\
            PatchedParentAddress INTEGER\n\
         );"

#define INSERT_MATCH_MAP_TABLE_STATEMENT "INSERT INTO  "MATCH_MAP_TABLE" ( TheSourceFileID, TheTargetFileID, SourceAddress, TargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress ) values ( '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u' );"
#define DELETE_MATCH_MAP_TABLE_STATEMENT "DELETE FROM "MATCH_MAP_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"SourceAddressIndex ON "MATCH_MAP_TABLE" ( SourceAddress )"
#define CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"TargetAddressIndex ON "MATCH_MAP_TABLE" ( TargetAddress )"

#define UNIDENTIFIED_BLOCKS_TABLE "UnidentifiedBlocks"
#define CREATE_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "CREATE TABLE "UNIDENTIFIED_BLOCKS_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            OldFileID INTEGER, \n\
            NewFileID INTEGER, \n\
            Type INTEGER, \n\
            Address INTEGER\n\
         );"
#define INSERT_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "INSERT INTO  "UNIDENTIFIED_BLOCKS_TABLE" ( Type, Address ) values ( '%u', '%u' );"

#define FUNCTION_MATCH_INFO_TABLE "FunctionMatchInfo"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "CREATE TABLE " FUNCTION_MATCH_INFO_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            TheSourceFileID INTEGER, \n\
            TheTargetFileID INTEGER, \n\
            SourceAddress INTEGER, \n\
            EndAddress INTEGER, \n\
            TargetAddress INTEGER, \n\
            BlockType INTEGER, \n\
            MatchRate INTEGER, \n\
            SourceFunctionName TEXT, \n\
            Type INTEGER, \n\
            TargetFunctionName TEXT, \n\
            MatchCountForTheSource INTEGER, \n\
            NoneMatchCountForTheSource INTEGER, \n\
            MatchCountWithModificationForTheSource INTEGER, \n\
            MatchCountForTheTarget INTEGER, \n\
            NoneMatchCountForTheTarget INTEGER, \n\
            MatchCountWithModificationForTheTarget INTEGER, \n\
            SecurityImplicationsScore INTEGER \n\
         );"
#define INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT "INSERT INTO  " FUNCTION_MATCH_INFO_TABLE" ( TheSourceFileID, TheTargetFileID, SourceAddress, EndAddress, TargetAddress, BlockType, MatchRate, SourceFunctionName, Type, TargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget ) values ( '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%s', '%u', '%s', '%u', '%u', '%u', '%u', '%u', '%u' );"
#define DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "DELETE FROM "FUNCTION_MATCH_INFO_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT "CREATE INDEX "FUNCTION_MATCH_INFO_TABLE"Index ON "FUNCTION_MATCH_INFO_TABLE" ( TheSourceFileID, TheTargetFileID, SourceAddress, TargetAddress )"

#define FILE_LIST_TABLE "FileList"
#define CREATE_FILE_LIST_TABLE_STATEMENT "CREATE TABLE " FILE_LIST_TABLE " ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            Type VARCHAR(25), \n\
            Filename VARCHAR(255), \n\
            FileID INTEGER, \n\
            FunctionAddress INTEGER\n\
         );"
#define INSERT_FILE_LIST_TABLE_STATEMENT "INSERT INTO  "FILE_LIST_TABLE" ( Type, Filename, FileID, FunctionAddress ) values ( '%s', '%s', '%d', '%d' );"

class SQLiteStorage : public Storage
{
private:
    sqlite3 *m_database;
    string m_databaseName;

public:
    SQLiteStorage(const char *DatabaseName = NULL);
    ~SQLiteStorage();

public:
    void SetFileInfo(FileInfo *p_file_info);
    int BeginTransaction();
    int EndTransaction();
    void Close();
    void AddBasicBlock(PBasicBlock pBasicBlock, int fileID = 0);
    void AddMapInfo(PMapInfo p_map_info, int fileID = 0);

    int ProcessTLV(BYTE Type, PBYTE Data, DWORD Length);

    void CreateTables();
    bool Open(char *DatabaseName);
    const char *GetDatabaseName();
    void CloseDatabase();
    bool ConnectDatabase(const char *DatabaseName);

    int GetLastInsertRowID();
    int ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);
    FunctionMatchInfoList QueryFunctionMatches(const char *query, int sourceID, int targetID);

    static int ReadFileListCallback(void *arg, int argc, char **argv, char **names);
    FileList ReadFileList();

    void InsertMatchMap(int sourceFileID, int targetFileID, va_t sourceAddress, va_t targetAddress, int matchType, int matchRate);

    void DeleteMatchInfo(int fileID, va_t functionAddress);
    void DeleteMatches(int srcFileID, int dstFileID);

    void AddFileInfo(char *fileType, const char *dbName, int fileID, va_t functionAddress);
    void AddFunctionMatchInfo(int srcFileID, int targetFileID, FunctionMatchInfo& functionMatchInfo);
};
