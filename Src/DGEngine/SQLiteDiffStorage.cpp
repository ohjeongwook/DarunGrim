#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

#include "SQLiteDiffStorage.h"
#include "Log.h"

char* GetFilename(char* full_pathname)
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

SQLiteDiffStorage::SQLiteDiffStorage(const char *DatabaseName)
{
    m_database = NULL;
    if (DatabaseName)
    {
        ConnectDatabase(DatabaseName);
        CreateTables();
    }
}

SQLiteDiffStorage::~SQLiteDiffStorage()
{
    CloseDatabase();
}

void SQLiteDiffStorage::CreateTables()
{
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FILE_LIST_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT);
}

bool SQLiteDiffStorage::Open(char *DatabaseName)
{
    m_databaseName = DatabaseName;
    return ConnectDatabase(DatabaseName);
}

bool SQLiteDiffStorage::ConnectDatabase(const char *DatabaseName)
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

const char *SQLiteDiffStorage::GetDatabaseName()
{
    return m_databaseName.c_str();
}

void SQLiteDiffStorage::CloseDatabase()
{
    //Close Database
    if (m_database)
    {
        sqlite3_close(m_database);
        m_database = NULL;
    }
}

int SQLiteDiffStorage::BeginTransaction()
{
    return ExecuteStatement(NULL, NULL, "BEGIN TRANSACTION");
}

int SQLiteDiffStorage::EndTransaction()
{
    return ExecuteStatement(NULL, NULL, "COMMIT TRANSACTION");
}

int SQLiteDiffStorage::GetLastInsertRowID()
{
    return (int)sqlite3_last_insert_rowid(m_database);
}

int SQLiteDiffStorage::ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...)
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

void SQLiteDiffStorage::Close()
{
    CloseDatabase();
}

int SQLiteDiffStorage::ReadOneMatchMapCallback(void *arg, int argc, char **argv, char **names)
{
    MatchMapList *p_pMatchMapList = (MatchMapList*)arg;
    MatchData *match_data = new MatchData();
    if (match_data)
    {
        match_data->Addresses[0] = strtoul10(argv[0]);
        match_data->Addresses[1] = strtoul10(argv[1]);
        match_data->Type = atoi(argv[3]);
        match_data->SubType = atoi(argv[4]);
        match_data->Status = atoi(argv[5]);
        match_data->MatchRate = atoi(argv[6]);
        match_data->UnpatchedParentAddress = strtoul10(argv[7]);
        match_data->PatchedParentAddress = strtoul10(argv[8]);
        p_pMatchMapList->Add(match_data);
    }
    return 0;
}

MatchMapList *SQLiteDiffStorage::ReadMatchMap(int sourceID, int targetID, int index, va_t address, bool erase)
{
    MatchMapList*pMatchMapList = new MatchMapList();
    MatchData match_data;
    memset(&match_data, 0, sizeof(match_data));

    if (erase)
    {
        ExecuteStatement(ReadOneMatchMapCallback, &pMatchMapList,
            "DELETE FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u",
            sourceID, targetID, index == 0 ? "SourceAddress" : "TargetAddress", address);
    }
    else if (address > 0)
    {
        ExecuteStatement(ReadOneMatchMapCallback, &pMatchMapList,
            "SELECT SourceAddress, TargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u",
            sourceID, targetID, index == 0 ? "SourceAddress" : "TargetAddress", address);

        if (match_data.Addresses[0] != 0)
        {
            for(MatchData *p_matchData : *pMatchMapList)
            {
                LogMessage(1, __FUNCTION__, "%u 0x%X returns %X-%X\r\n",
                    index,
                    address,
                    p_matchData->Addresses[0],
                    p_matchData->Addresses[1]
                );
            }
        }
    }

    return pMatchMapList;
}

int SQLiteDiffStorage::ReadMatchMapCallback(void *arg, int argc, char **argv, char **names)
{
    MatchResults* p_matchResults = (MatchResults*)arg;

    MatchData match_data;
    DWORD SourceAddress = strtoul10(argv[0]);
    DWORD TargetAddress = strtoul10(argv[1]);
    match_data.Type = atoi(argv[3]);
    match_data.SubType = atoi(argv[4]);
    match_data.Status = atoi(argv[5]);
    match_data.MatchRate = atoi(argv[6]);
    match_data.UnpatchedParentAddress = strtoul10(argv[7]);
    match_data.PatchedParentAddress = strtoul10(argv[8]);
    match_data.Addresses[0] = SourceAddress;
    match_data.Addresses[1] = TargetAddress;
    p_matchResults->AddMatchData(match_data, __FUNCTION__);
    return 0;
}

MatchResults* SQLiteDiffStorage::ReadMatchResults(int sourceID, int targetID)
{
    MatchResults* p_matchResults = new MatchResults();

    ExecuteStatement(ReadMatchMapCallback, p_matchResults,
        "SELECT SourceAddress, TargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress From MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u",
        sourceID, targetID);

    return p_matchResults;
}

int SQLiteDiffStorage::QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names)
{
    FunctionMatchInfoList *pFunctionMatchList = (FunctionMatchInfoList*)arg;
    FunctionMatchInfo function_match_info;
    function_match_info.SourceAddress = strtoul10(argv[0]);
    function_match_info.EndAddress = strtoul10(argv[1]);
    function_match_info.TargetAddress = strtoul10(argv[2]);
    function_match_info.BlockType = atoi(argv[3]);
    function_match_info.MatchRate = atoi(argv[4]);
    function_match_info.SourceFunctionName = string(argv[5]);
    function_match_info.Type = atoi(argv[6]);
    function_match_info.TargetFunctionName = string(argv[7]);
    function_match_info.MatchCountForTheSource = atoi(argv[8]);
    function_match_info.NoneMatchCountForTheSource = atoi(argv[9]);
    function_match_info.MatchCountWithModificationForTheSource = atoi(argv[10]);
    function_match_info.MatchCountForTheTarget = atoi(argv[11]);
    function_match_info.NoneMatchCountForTheTarget = atoi(argv[12]);
    function_match_info.MatchCountWithModificationForTheTarget = atoi(argv[13]);
    pFunctionMatchList->Add(function_match_info);
    return 0;
}

FunctionMatchInfoList SQLiteDiffStorage::QueryFunctionMatches(const char *query, int sourceID, int targetID)
{
    FunctionMatchInfoList functionMatchList;
    ExecuteStatement(QueryFunctionMatchesCallback, &functionMatchList, query, sourceID, targetID);
    return functionMatchList;
}

int SQLiteDiffStorage::ReadFileListCallback(void *arg, int argc, char **argv, char **names)
{
    FileList *file_list = (FileList*)arg;
    if (file_list)
    {
        if (!_stricmp(argv[0], "source"))
        {
            file_list->SourceFilename = GetFilename(argv[1]);
        }
        else if (!_stricmp(argv[0], "target"))
        {
            file_list->TargetFilename = GetFilename(argv[1]);
        }
    }
    return 0;
}

void SQLiteDiffStorage::InsertMatchMap(int sourceFileID, int targetFileID, va_t sourceAddress, va_t targetAddress, int matchType, int matchRate)
{
    ExecuteStatement(NULL, NULL,
        INSERT_MATCH_MAP_TABLE_STATEMENT,
        sourceFileID,
        targetFileID,
        sourceAddress,
        targetAddress,
        TYPE_MATCH,
        INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH,
        0,
        0,
        matchRate,
        0,
        0);

}

void SQLiteDiffStorage::DeleteMatchInfo(int fileID, va_t functionAddress)
{
    ExecuteStatement(NULL, NULL,
        "DELETE FROM  MatchMap WHERE TheSourceFileID='%d' AND SourceAddress IN (SELECT StartAddress FROM BasicBlock WHERE FileID = '%d' AND FunctionAddress='%d')",
        fileID, fileID, functionAddress);

    ExecuteStatement(NULL, NULL,
        "DELETE FROM  FunctionMatchInfo WHERE TheSourceFileID='%d' AND SourceAddress ='%d'",
        fileID, functionAddress);

    ExecuteStatement(NULL, NULL,
        "DELETE FROM  MatchMap WHERE TheTargetFileID='%d' AND TargetAddress IN (SELECT StartAddress FROM BasicBlock WHERE FileID = '%d' AND FunctionAddress='%d')",
        fileID, fileID, functionAddress);

    ExecuteStatement(NULL, NULL,
        "DELETE FROM  FunctionMatchInfo WHERE TheTargetFileID='%d' AND TargetAddress ='%d'",
        fileID, functionAddress);
}

void SQLiteDiffStorage::DeleteMatches(int srcFileID, int dstFileID)
{
    ExecuteStatement(NULL, NULL, DELETE_MATCH_MAP_TABLE_STATEMENT, srcFileID, dstFileID);
    ExecuteStatement(NULL, NULL, DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT, srcFileID, dstFileID);
}

void SQLiteDiffStorage::AddFileInfo(char *fileType, const char *dbName, int fileID, va_t functionAddress)
{
    ExecuteStatement(NULL, NULL, INSERT_FILE_LIST_TABLE_STATEMENT, fileType, dbName, fileID, functionAddress);
}

void SQLiteDiffStorage::AddFunctionMatchInfo(int srcFileID, int targetFileID, FunctionMatchInfo& functionMatchInfo)
{
    ExecuteStatement(NULL, NULL, INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT,
        srcFileID,
        targetFileID,
        functionMatchInfo.SourceAddress,
        functionMatchInfo.EndAddress,
        functionMatchInfo.TargetAddress,
        functionMatchInfo.BlockType,
        functionMatchInfo.MatchRate,
        functionMatchInfo.SourceFunctionName,
        functionMatchInfo.Type,
        functionMatchInfo.TargetFunctionName,
        functionMatchInfo.MatchCountForTheSource,
        functionMatchInfo.NoneMatchCountForTheSource,
        functionMatchInfo.MatchCountWithModificationForTheSource,
        functionMatchInfo.MatchCountForTheTarget,
        functionMatchInfo.NoneMatchCountForTheTarget,
        functionMatchInfo.MatchCountWithModificationForTheTarget
    );
}
