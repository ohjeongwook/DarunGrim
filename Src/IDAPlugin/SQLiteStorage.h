#pragma once
#include <stdio.h>
#include <string>

#include "Common.h"
#include "Storage.h"

#include "sqlite3.h"

using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;

#define FILE_INFO_TABLE "FileInfo"
#define CREATE_FILE_INFO_TABLE_STATEMENT "CREATE TABLE " FILE_INFO_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            OriginalFilePath TEXT,\n\
            ComputerName VARCHAR(100),\n\
            UserName VARCHAR(100),\n\
            CompanyName VARCHAR(100),\n\
            FileVersion VARCHAR(100),\n\
            FileDescription VARCHAR(100),\n\
            InternalName VARCHAR(100),\n\
            ProductName VARCHAR(100),\n\
            ModifiedTime VARCHAR(100),\n\
            MD5Sum VARCHAR(100)\n\
);"
#define INSERT_FILE_INFO_TABLE_STATEMENT "INSERT INTO  " FILE_INFO_TABLE" (OriginalFilePath,ComputerName,UserName,CompanyName,FileVersion,FileDescription,InternalName,ProductName,ModifiedTime,MD5Sum) values (%Q,%Q,%Q,%Q,%Q,%Q,%Q,%Q,%Q,%Q);"

#define MAP_INFO_TABLE "MapInfo"
#define CREATE_MAP_INFO_TABLE_STATEMENT "CREATE TABLE " MAP_INFO_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            Type INTEGER,\n\
            SrcBlock INTEGER,\n\
            SrcBlockEnd INTEGER,\n\
            Dst INTEGER\n\
        );"
#define CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT "CREATE INDEX "MAP_INFO_TABLE"Index ON "MAP_INFO_TABLE" (SrcBlock)"
#define INSERT_MAP_INFO_TABLE_STATEMENT "INSERT INTO  " MAP_INFO_TABLE" (FileID,Type,SrcBlock,SrcBlockEnd,Dst) values ('%u','%u','%u','%u','%u');"

#define BASIC_BLOCK_TABLE "BasicBlock"
#define CREATE_BASIC_BLOCK_TABLE_STATEMENT "CREATE TABLE " BASIC_BLOCK_TABLE" (\n\
            id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
            FileID INTEGER,\n\
            StartAddress INTEGER,\n\
            EndAddress INTEGER,\n\
            Flag INTEGER,\n\
            FunctionAddress INTEGER,\n\
            BlockType INTEGER,\n\
            Name TEXT,\n\
            DisasmLines TEXT,\n\
            Fingerprint TEXT\n\
);"

#define CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"FunctionAddressIndex ON "BASIC_BLOCK_TABLE" (FunctionAddress)"

#define CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"StartAddressIndex ON "BASIC_BLOCK_TABLE" (StartAddress)"

#define CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"EndAddressIndex ON "BASIC_BLOCK_TABLE" (EndAddress)"

//#define CREATE_BASIC_BLOCK_TABLE_INDEX_STATEMENT "CREATE INDEX "BASIC_BLOCK_TABLE"AddressIndex ON "BASIC_BLOCK_TABLE" (FileID,StartAddress,EndAddress,Name,Fingerprint)"
#define INSERT_BASIC_BLOCK_TABLE_STATEMENT "INSERT INTO  " BASIC_BLOCK_TABLE" (FileID,StartAddress,EndAddress,Flag,FunctionAddress,BlockType,Name,DisasmLines,Fingerprint) values ('%u','%u','%u','%u','%u','%u',%Q,%Q,%Q);"
#define UPDATE_BASIC_BLOCK_TABLE_NAME_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET Name=%Q WHERE StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET FunctionAddress='%u',BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_BLOCK_TYPE_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_DISASM_LINES_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET DisasmLines=%Q WHERE StartAddress='%u';"
#define UPDATE_BASIC_BLOCK_TABLE_FINGERPRINT_STATEMENT "UPDATE " BASIC_BLOCK_TABLE" SET Fingerprint=%Q WHERE StartAddress='%u';"

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

#define CREATE_FILE_LIST_TABLE_STATEMENT "CREATE TABLE " FILE_LIST_TABLE " ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            Type VARCHAR(25), \n\
            Filename VARCHAR(255), \n\
            FileID INTEGER, \n\
            FunctionAddress INTEGER\n\
         );"

#define INSERT_FILE_LIST_TABLE_STATEMENT "INSERT INTO  "FILE_LIST_TABLE" ( Type, Filename, FileID, FunctionAddress ) values ( '%s', '%s', '%d', '%d' );"

#define UNIDENTIFIED_BLOCKS_TABLE "UnidentifiedBlocks"
#define CREATE_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "CREATE TABLE "UNIDENTIFIED_BLOCKS_TABLE" ( \n\
            id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
            OldFileID INTEGER, \n\
            NewFileID INTEGER, \n\
            Type INTEGER, \n\
            Address INTEGER\n\
         );"
#define INSERT_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "INSERT INTO  "UNIDENTIFIED_BLOCKS_TABLE" ( Type, Address ) values ( '%u', '%u' );"

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
    static int display_callback(void *NotUsed, int argc, char **argv, char **azColName);
    static int ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names);
    static int ReadRecordStringCallback(void *arg, int argc, char **argv, char **names);

    static int ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names);
    void ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap);

    char *ReadFingerPrint(int fileID, va_t address);
    char *ReadName(int fileID, va_t address);
    va_t ReadBlockStartAddress(int fileID, va_t address);

    static int ReadBasicBlockDataCallback(void *arg, int argc, char **argv, char **names);

    static int ReadMapInfoCallback(void *arg, int argc, char **argv, char **names);
    multimap <va_t, PMapInfo> *ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false);

    static int ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names);
    list<BLOCK> ReadFunctionMemberAddresses(int fileID, va_t function_address);

    static int QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names);

    char *GetOriginalFilePath(int fileID);

    char *ReadDisasmLine(int fileID, va_t startAddress);

    static int ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names);
    PBasicBlock ReadBasicBlock(int fileID, va_t address);

    void UpdateBasicBlock(int fileID, va_t address1, va_t address2);
};
