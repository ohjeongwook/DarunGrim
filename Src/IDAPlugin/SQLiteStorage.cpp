#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>
#include <map>
#include <iostream>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

#include "Common.h"
#include "SQLiteStorage.h"
#include "Log.h"

SQLiteStorage::SQLiteStorage(const char *DatabaseName)
{
    m_database = NULL;
    if (DatabaseName)
    {
        ConnectDatabase(DatabaseName);
        CreateTables();
    }
}

SQLiteStorage::~SQLiteStorage()
{
    CloseDatabase();
}

void SQLiteStorage::CreateTables()
{
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);

    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT);
}

bool SQLiteStorage::Open(char *DatabaseName)
{
    m_databaseName = DatabaseName;
    return ConnectDatabase(DatabaseName);
}

bool SQLiteStorage::ConnectDatabase(const char *DatabaseName)
{
    //Database Setup
    m_databaseName = DatabaseName;
    int rc = sqlite3_open(DatabaseName, &m_database);
    if (rc)
    {
        printf("Opening Database [%s] Failed\n", DatabaseName);
        sqlite3_close(m_database);
        m_database = NULL;
        return FALSE;
    }
    return TRUE;
}

const char *SQLiteStorage::GetDatabaseName()
{
    return m_databaseName.c_str();
}

void SQLiteStorage::CloseDatabase()
{
    //Close Database
    if (m_database)
    {
        sqlite3_close(m_database);
        m_database = NULL;
    }
}

int SQLiteStorage::BeginTransaction()
{
    return ExecuteStatement(NULL, NULL, "BEGIN TRANSACTION");
}

int SQLiteStorage::EndTransaction()
{
    return ExecuteStatement(NULL, NULL, "COMMIT TRANSACTION");
}

int SQLiteStorage::GetLastInsertRowID()
{
    return (int)sqlite3_last_insert_rowid(m_database);
}

int SQLiteStorage::ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...)
{
    int debug = 0;

    if (m_database)
    {
        int rc = 0;
        char *statement_buffer = NULL;
        char *zErrMsg = 0;

        va_list args;
        va_start(args, format);
#ifdef USE_VSNPRINTF
        int statement_buffer_len = 0;

        while (1)
        {
            statement_buffer_len += 1024;
            statement_buffer = (char*)malloc(statement_buffer_len);
            memset(statement_buffer, 0, statement_buffer_len);
            if (statement_buffer && _vsnprintf(statement_buffer, statement_buffer_len, format, args) != -1)
            {
                free(statement_buffer);
                break;
            }

            if (!statement_buffer)
                break;
            free(statement_buffer);
        }
#else
        statement_buffer = sqlite3_vmprintf(format, args);
#endif
        va_end(args);

        if (debug > 1)
        {
            LogMessage(1, __FUNCTION__, TEXT("Executing [%s]\n"), statement_buffer);
        }

        if (statement_buffer)
        {
            rc = sqlite3_exec(m_database, statement_buffer, callback, context, &zErrMsg);

            if (rc != SQLITE_OK)
            {
                if (debug > 0)
                {
#ifdef IDA_PLUGIN				
                    LogMessage(1, __FUNCTION__, "SQL error: [%s] [%s]\n", statement_buffer, zErrMsg);
#else
                    LogMessage(1, __FUNCTION__, "SQL error: [%s] [%s]\n", statement_buffer, zErrMsg);
#endif
                }
            }
#ifdef USE_VSNPRINTF
            free(statement_buffer);
#else
            sqlite3_free(statement_buffer);
#endif
        }

        return rc;
    }
    return SQLITE_ERROR;
}

void SQLiteStorage::SetFileInfo(FileInfo *pFileInfo)
{
    ExecuteStatement(NULL, NULL, INSERT_FILE_INFO_TABLE_STATEMENT,
        pFileInfo->OriginalFilePath,
        pFileInfo->ComputerName,
        pFileInfo->UserName,
        pFileInfo->CompanyName,
        pFileInfo->FileVersion,
        pFileInfo->FileDescription,
        pFileInfo->InternalName,
        pFileInfo->ProductName,
        pFileInfo->ModifiedTime,
        pFileInfo->MD5Sum
    );
}

void SQLiteStorage::AddBasicBlock(PBasicBlock pBasicBlock, int fileID)
{
    char *fingerprintStr = NULL;
    if (pBasicBlock->FingerprintLen > 0)
    {
        fingerprintStr = (char*)malloc(pBasicBlock->FingerprintLen * 2 + 10);
        if (fingerprintStr)
        {
            memset(fingerprintStr, 0, pBasicBlock->FingerprintLen * 2 + 10);
            char tmp_buffer[10];
            for (int i = 0; i < pBasicBlock->FingerprintLen; i++)
            {
                _snprintf(tmp_buffer, sizeof(tmp_buffer) - 1, "%.2x", pBasicBlock->Data[pBasicBlock->NameLen + pBasicBlock->DisasmLinesLen + i] & 0xff);
                tmp_buffer[sizeof(tmp_buffer) - 1] = NULL;
                strncat(fingerprintStr, tmp_buffer, sizeof(tmp_buffer));
            }
        }
    }

    ExecuteStatement(NULL, NULL, INSERT_BASIC_BLOCK_TABLE_STATEMENT,
        fileID,
        pBasicBlock->StartAddress,
        pBasicBlock->EndAddress,
        pBasicBlock->Flag,
        pBasicBlock->FunctionAddress,
        pBasicBlock->BlockType,
        pBasicBlock->Data,
        pBasicBlock->Data + pBasicBlock->NameLen,
        fingerprintStr ? fingerprintStr : ""
    );

    if (fingerprintStr)
        free(fingerprintStr);
}

void SQLiteStorage::AddMapInfo(PMapInfo pMapInfo, int fileID)
{
    ExecuteStatement(NULL, NULL, INSERT_MAP_INFO_TABLE_STATEMENT,
        fileID,
        pMapInfo->Type,
        pMapInfo->SrcBlock,
        pMapInfo->SrcBlockEnd,
        pMapInfo->Dst
    );
}

void SQLiteStorage::Close()
{
    CloseDatabase();
}

int SQLiteStorage::ProcessTLV(BYTE Type, PBYTE Data, DWORD Length)
{
    static int fileID = 0;
    bool Status = FALSE;
    static va_t CurrentAddress = 0L;

    switch (Type)
    {
    case BASIC_BLOCK:
        if (sizeof(BasicBlock) <= Length)
        {
            AddBasicBlock((PBasicBlock)Data, fileID);
        }
        break;

    case MAP_INFO:
        if (sizeof(MapInfo) <= Length)
        {
            AddMapInfo((PMapInfo)Data, fileID);
        }
        break;

    case FILE_INFO:
        if (sizeof(FileInfo) <= Length)
        {
            SetFileInfo((PFileInfo)Data);
            fileID = GetLastInsertRowID();
        }
        break;

    }
    Status = TRUE;
    return fileID;
}


int SQLiteStorage::display_callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++) {
        LogMessage(1, __FUNCTION__, "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    return 0;
}

int SQLiteStorage::ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names)
{
#if DEBUG_LEVEL > 2
    printf("%s: arg=%x %d\n", __FUNCTION__, arg, argc);
    for (int i = 0; i < argc; i++)
    {
        printf("	[%d] %s=%s\n", i, names[i], argv[i]);
    }
#endif
     *(int*)arg = atoi(argv[0]);
    return 0;
}

int SQLiteStorage::ReadRecordStringCallback(void *arg, int argc, char **argv, char **names)
{
#if DEBUG_LEVEL > 2
    printf("%s: arg=%x %d\n", __FUNCTION__, arg, argc);
    for (int i = 0; i < argc; i++)
    {
        printf("	[%d] %s=%s\n", i, names[i], argv[i]);
    }
#endif
     *(char**)arg = _strdup(argv[0]);
    return 0;
}

int SQLiteStorage::ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names)
{
    unordered_set <va_t> *FunctionAddressHash = (unordered_set <va_t>*)arg;
    if (FunctionAddressHash)
    {
#if DEBUG_LEVEL > 1
        if (DebugLevel & 1) Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID, argv[0], strtoul10(argv[0]));
#endif
        FunctionAddressHash->insert(strtoul10(argv[0]));
    }
    return 0;
}

void SQLiteStorage::ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap)
{
    ExecuteStatement(ReadFunctionAddressesCallback, &functionAddressMap, "SELECT DISTINCT(FunctionAddress) FROM BasicBlock WHERE FileID = %u AND BlockType = %u", fileID, FUNCTION_BLOCK);
}

char *SQLiteStorage::ReadFingerPrint(int fileID, va_t address)
{
    char *fingerPrintString = NULL;

    ExecuteStatement(ReadRecordStringCallback, &fingerPrintString, "SELECT Fingerprint FROM BasicBlock WHERE FileID = %u and StartAddress = %u", fileID, address);
    return fingerPrintString;
}

char *SQLiteStorage::ReadName(int fileID, va_t address)
{
    char *name = NULL;
    ExecuteStatement(ReadRecordStringCallback, &name,
        "SELECT Name FROM BasicBlock WHERE FileID = %u and StartAddress = %u", fileID, address);
    return name;
}

va_t SQLiteStorage::ReadBlockStartAddress(int fileID, va_t address)
{
    va_t blockAddress;
    ExecuteStatement(ReadRecordIntegerCallback, &blockAddress,
        "SELECT StartAddress FROM BasicBlock WHERE FileID = %u and StartAddress <=  %u  and %u <=  EndAddress LIMIT 1",
        fileID, address, address);
    return blockAddress;
}


unsigned char *HexToBytesWithLengthAmble(char *HexBytes);

int SQLiteStorage::ReadMapInfoCallback(void *arg, int argc, char **argv, char **names)
{
    multimap <va_t, PMapInfo> *p_map_info_map = (multimap <va_t, PMapInfo>*)arg;

    PMapInfo p_map_info = new MapInfo;
    p_map_info->Type = strtoul10(argv[0]);
    p_map_info->SrcBlock = strtoul10(argv[1]);
    p_map_info->SrcBlockEnd = strtoul10(argv[2]);
    p_map_info->Dst = strtoul10(argv[3]);
#if DEBUG_LEVEL > 1
    Logger.Log(10, "%s: ID = %d strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID,
        argv[0], strtoul10(argv[0]),
        argv[1], strtoul10(argv[1]),
        argv[2], strtoul10(argv[2]),
        argv[3], strtoul10(argv[3])
    );
#endif
    p_map_info_map->insert(AddressPMapInfoPair(p_map_info->SrcBlock, p_map_info));
    return 0;
}

multimap <va_t, PMapInfo> *SQLiteStorage::ReadMapInfo(int fileID, va_t address, bool isFunction)
{
    multimap <va_t, PMapInfo> *p_map_info_map = new multimap <va_t, PMapInfo>();
    if (address == 0)
    {
        ExecuteStatement(ReadMapInfoCallback, (void*)p_map_info_map,
            "SELECT Type, SrcBlock, SrcBlockEnd, Dst From MapInfo WHERE FileID = %u",
            fileID);
    }
    else
    {
        if (isFunction)
        {
            p_map_info_map = ReadMapInfo(fileID, address, isFunction);

            ExecuteStatement(ReadMapInfoCallback, (void*)p_map_info_map,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From MapInfo "
                "WHERE FileID = %u "
                "AND ( SrcBlock IN ( SELECT StartAddress FROM BasicBlock WHERE FunctionAddress='%d') )",
                fileID, address);
        }
        else
        {
            ExecuteStatement(ReadMapInfoCallback, (void*)p_map_info_map,
                "SELECT Type, SrcBlock, SrcBlockEnd, Dst From MapInfo "
                "WHERE FileID = %u "
                "AND SrcBlock  = '%d'",
                fileID, address);
        }
    }

    return p_map_info_map;
}

int SQLiteStorage::ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names)
{
    list <BLOCK> *p_address_list = (list <BLOCK>*)arg;
    if (p_address_list)
    {
#if DEBUG_LEVEL > 1
        if (DebugLevel & 1) Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d strtoul10(%s) = 0x%X\n", __FUNCTION__, fileID, argv[0], strtoul10(argv[0]));
#endif
        BLOCK block;
        block.Start = strtoul10(argv[0]);
        block.End = strtoul10(argv[1]);
        p_address_list->push_back(block);
    }
    return 0;
}

list<BLOCK> SQLiteStorage::ReadFunctionMemberAddresses(int fileID, va_t function_address)
{
    list<BLOCK> block_list;

    ExecuteStatement(ReadFunctionMemberAddressesCallback, (void*)&block_list,
        "SELECT StartAddress, EndAddress FROM BasicBlock WHERE FileID = '%d' AND FunctionAddress='%d'"
        "ORDER BY ID ASC",
        fileID, function_address);

    return block_list;
}

char *GetFilename(char *full_pathname)
{
    for (int i = strlen(full_pathname) - 1; i > 0; i--)
    {
        if (full_pathname[i] == '\\')
        {
            return full_pathname + i + 1;
        }
    }

    return full_pathname;
}

char *SQLiteStorage::GetOriginalFilePath(int fileID)
{
    char *originalFilePath;
    ExecuteStatement(ReadRecordStringCallback, &originalFilePath,
        "SELECT OriginalFilePath FROM FileInfo WHERE id = %u", fileID);

    return originalFilePath;
}

char *SQLiteStorage::ReadDisasmLine(int fileID, va_t startAddress)
{
    char *disasmLines = NULL;
    ExecuteStatement(ReadRecordStringCallback, &disasmLines, "SELECT DisasmLines FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        fileID, startAddress);
    return disasmLines;
}

int SQLiteStorage::ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names)
{
    PBasicBlock p_basic_block = (PBasicBlock)arg;
    p_basic_block->StartAddress = strtoul10(argv[0]);
    p_basic_block->EndAddress = strtoul10(argv[1]);
    p_basic_block->Flag = strtoul10(argv[2]);
    p_basic_block->FunctionAddress = strtoul10(argv[3]);
    p_basic_block->BlockType = strtoul10(argv[4]);
    p_basic_block->FingerprintLen = strlen(argv[5]);

    LogMessage(0, __FUNCTION__, "%X Block Type: %d\n", p_basic_block->StartAddress, p_basic_block->BlockType);

    if (p_basic_block->BlockType == FUNCTION_BLOCK)
    {
        LogMessage(0, __FUNCTION__, "Function Block: %X\n", p_basic_block->StartAddress);
    }
    return 0;
}

PBasicBlock SQLiteStorage::ReadBasicBlock(int fileID, va_t address)
{
    PBasicBlock p_basic_block = (PBasicBlock)malloc(sizeof(BasicBlock));
    ExecuteStatement(ReadBasicBlockCallback, p_basic_block,
        "SELECT StartAddress, EndAddress, Flag, FunctionAddress, BlockType, FingerPrint FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        fileID,
        address);

    return p_basic_block;
}

void SQLiteStorage::UpdateBasicBlock(int fileID, va_t address1, va_t address2)
{
    ExecuteStatement(NULL, NULL, UPDATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_STATEMENT,
        address2, address2 == address1 ? FUNCTION_BLOCK : UNKNOWN_BLOCK, fileID, address1);
}
