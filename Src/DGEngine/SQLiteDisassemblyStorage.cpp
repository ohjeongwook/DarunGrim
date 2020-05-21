#pragma once
#include <stdio.h>
#include <string>
#include <unordered_set>

using namespace std;
using namespace stdext;

#include "sqlite3.h"

#include "SQLiteDisassemblyStorage.h"
#include "Log.h"

SQLiteDisassemblyStorage::SQLiteDisassemblyStorage(const char *DatabaseName)
{
    db = NULL;
    if (DatabaseName)
    {
        CreateDatabase(DatabaseName);
        CreateTables();
    }
}

SQLiteDisassemblyStorage::~SQLiteDisassemblyStorage()
{
    CloseDatabase();
}

void SQLiteDisassemblyStorage::CreateTables()
{
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);

    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FILE_LIST_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT);
}

bool SQLiteDisassemblyStorage::Open(char *DatabaseName)
{
    m_DatabaseName = DatabaseName;
    return CreateDatabase(DatabaseName);
}

bool SQLiteDisassemblyStorage::CreateDatabase(const char *DatabaseName)
{
    //Database Setup
    m_DatabaseName = DatabaseName;
    int rc = sqlite3_open(DatabaseName, &db);
    if (rc)
    {
        printf("Opening Database [%s] Failed\n", DatabaseName);
        sqlite3_close(db);
        db = NULL;
        return FALSE;
    }
    return TRUE;
}

const char *SQLiteDisassemblyStorage::GetDatabaseName()
{
    return m_DatabaseName.c_str();
}

void SQLiteDisassemblyStorage::CloseDatabase()
{
    //Close Database
    if (db)
    {
        sqlite3_close(db);
        db = NULL;
    }
}

int SQLiteDisassemblyStorage::BeginTransaction()
{
    return ExecuteStatement(NULL, NULL, "BEGIN TRANSACTION");
}

int SQLiteDisassemblyStorage::EndTransaction()
{
    return ExecuteStatement(NULL, NULL, "COMMIT");
}

int SQLiteDisassemblyStorage::GetLastInsertRowID()
{
    return (int)sqlite3_last_insert_rowid(db);
}

int SQLiteDisassemblyStorage::ExecuteStatement(sqlite3_callback callback, void *context, const char *format, ...)
{
    int debug = 0;

    if (db)
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
            LogMessage(1, __FUNCTION__, "Executing [%s]\n", statement_buffer);
        }

        if (statement_buffer)
        {
            rc = sqlite3_exec(db, statement_buffer, callback, context, &zErrMsg);

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

void SQLiteDisassemblyStorage::SetFileInfo(FileInfo *pFileInfo)
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

void SQLiteDisassemblyStorage::AddBasicBlock(PBasicBlock pBasicBlock, int fileID)
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

void SQLiteDisassemblyStorage::AddMapInfo(PMapInfo pMapInfo, int fileID)
{
    ExecuteStatement(NULL, NULL, INSERT_MAP_INFO_TABLE_STATEMENT,
        fileID,
        pMapInfo->Type,
        pMapInfo->SrcBlock,
        pMapInfo->SrcBlockEnd,
        pMapInfo->Dst
    );
}

void SQLiteDisassemblyStorage::EndAnalysis()
{
    CloseDatabase();
}

int SQLiteDisassemblyStorage::ProcessTLV(BYTE Type, PBYTE Data, DWORD Length)
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


int SQLiteDisassemblyStorage::display_callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++) {
        LogMessage(1, __FUNCTION__, "%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    return 0;
}

int SQLiteDisassemblyStorage::ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names)
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

int SQLiteDisassemblyStorage::ReadRecordStringCallback(void *arg, int argc, char **argv, char **names)
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

int SQLiteDisassemblyStorage::ReadFunctionAddressesCallback(void *arg, int argc, char **argv, char **names)
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

void SQLiteDisassemblyStorage::ReadFunctionAddressMap(int fileID, unordered_set <va_t>& functionAddressMap)
{
    ExecuteStatement(ReadFunctionAddressesCallback, &functionAddressMap, "SELECT DISTINCT(FunctionAddress) FROM BasicBlock WHERE FileID = %u AND BlockType = %u", fileID, FUNCTION_BLOCK);
}

char *SQLiteDisassemblyStorage::ReadFingerPrint(int fileID, va_t address)
{
    char *fingerPrintString = NULL;

    ExecuteStatement(ReadRecordStringCallback, &fingerPrintString, "SELECT Fingerprint FROM BasicBlock WHERE FileID = %u and StartAddress = %u", fileID, address);
    return fingerPrintString;
}

char *SQLiteDisassemblyStorage::ReadName(int fileID, va_t address)
{
    char *name = NULL;
    ExecuteStatement(ReadRecordStringCallback, &name,
        "SELECT Name FROM BasicBlock WHERE FileID = %u and StartAddress = %u", fileID, address);
    return name;
}

va_t SQLiteDisassemblyStorage::ReadBlockStartAddress(int fileID, va_t address)
{
    va_t blockAddress;
    ExecuteStatement(ReadRecordIntegerCallback, &blockAddress,
        "SELECT StartAddress FROM BasicBlock WHERE FileID = %u and StartAddress <=  %u  and %u <=  EndAddress LIMIT 1",
        fileID, address, address);
    return blockAddress;
}


unsigned char *HexToBytesWithLengthAmble(char *HexBytes);

int SQLiteDisassemblyStorage::ReadBasicBlockDataCallback(void *arg, int argc, char **argv, char **names)
{
    AnalysisInfo *ClientAnalysisInfo = (AnalysisInfo*)arg;
    if (argv[1] && argv[1][0] != NULL)
    {
        va_t Address = strtoul10(argv[0]);
        unsigned char *FingerprintStr = HexToBytesWithLengthAmble(argv[1]);
        if (FingerprintStr)
        {
            ClientAnalysisInfo->address_fingerprint_map.insert(AddressFingerPrintAddress_Pair(Address, FingerprintStr));
        }

        if (strtoul10(argv[3]) == 1 && strlen(argv[2]) > 0)
        {
            char *name = argv[2];
            ClientAnalysisInfo->name_map.insert(NameAddress_Pair(name, Address));
        }
    }
    return 0;
}

void SQLiteDisassemblyStorage::ReadBasicBlockInfo(int fileID, char *conditionStr, AnalysisInfo *analysisInfo)
{
    ExecuteStatement(ReadBasicBlockDataCallback,
        (void*)analysisInfo,
        "SELECT StartAddress, Fingerprint, Name, BlockType FROM BasicBlock WHERE FileID = %u %s",
        fileID,
        conditionStr);
}

int SQLiteDisassemblyStorage::ReadMapInfoCallback(void *arg, int argc, char **argv, char **names)
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
    p_map_info_map->insert(AddrPMapInfo_Pair(p_map_info->SrcBlock, p_map_info));
    return 0;
}

multimap <va_t, PMapInfo> *SQLiteDisassemblyStorage::ReadMapInfo(int fileID, va_t address, bool isFunction)
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

int SQLiteDisassemblyStorage::ReadOneMatchMapCallback(void *arg, int argc, char **argv, char **names)
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

MatchMapList *SQLiteDisassemblyStorage::ReadMatchMap(int sourceID, int targetID, int index, va_t address, bool erase)
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
            for (vector<MatchData*>::iterator it = pMatchMapList->begin(); it != pMatchMapList->end(); it++)
            {
                LogMessage(1, __FUNCTION__, "%u 0x%X returns %X-%X\r\n",
                    index,
                    address,
                    (*it)->Addresses[0],
                    (*it)->Addresses[1]
                );
            }
        }
    }

    return pMatchMapList;
}

int SQLiteDisassemblyStorage::ReadMatchMapCallback(void *arg, int argc, char **argv, char **names)
{
    MatchResults *DiffResults = (MatchResults*)arg;

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
    DiffResults->AddMatchData(match_data, __FUNCTION__);
    return 0;
}

MatchResults *SQLiteDisassemblyStorage::ReadMatchResults(int sourceID, int targetID)
{
    MatchResults *DiffResults = new MatchResults();

    ExecuteStatement(
        ReadMatchMapCallback,
        DiffResults,
        "SELECT SourceAddress, TargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress From MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u",
        sourceID, targetID);

    return DiffResults;
}

int SQLiteDisassemblyStorage::ReadFunctionMemberAddressesCallback(void *arg, int argc, char **argv, char **names)
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

list<BLOCK> SQLiteDisassemblyStorage::ReadFunctionMemberAddresses(int fileID, va_t function_address)
{
    list<BLOCK> block_list;

    ExecuteStatement(ReadFunctionMemberAddressesCallback, (void*)&block_list,
        "SELECT StartAddress, EndAddress FROM BasicBlock WHERE FileID = '%d' AND FunctionAddress='%d'"
        "ORDER BY ID ASC",
        fileID, function_address);

    return block_list;
}

int SQLiteDisassemblyStorage::QueryFunctionMatchesCallback(void *arg, int argc, char **argv, char **names)
{
    FunctionMatchInfoList *pFunctionMatchList = (FunctionMatchInfoList*)arg;
    FunctionMatchInfo function_match_info;
    function_match_info.SourceAddress = strtoul10(argv[0]);
    function_match_info.EndAddress = strtoul10(argv[1]);
    function_match_info.TargetAddress = strtoul10(argv[2]);
    function_match_info.BlockType = atoi(argv[3]);
    function_match_info.MatchRate = atoi(argv[4]);
    function_match_info.SourceFunctionName = _strdup(argv[5]);
    function_match_info.Type = atoi(argv[6]);
    function_match_info.TargetFunctionName = _strdup(argv[7]);
    function_match_info.MatchCountForTheSource = atoi(argv[8]);
    function_match_info.NoneMatchCountForTheSource = atoi(argv[9]);
    function_match_info.MatchCountWithModificationForTheSource = atoi(argv[10]);
    function_match_info.MatchCountForTheTarget = atoi(argv[11]);
    function_match_info.NoneMatchCountForTheTarget = atoi(argv[12]);
    function_match_info.MatchCountWithModificationForTheTarget = atoi(argv[13]);
    pFunctionMatchList->Add(function_match_info);
    return 0;
}

FunctionMatchInfoList SQLiteDisassemblyStorage::QueryFunctionMatches(const char *query, int sourceID, int targetID)
{
    FunctionMatchInfoList functionMatchList;
    ExecuteStatement(QueryFunctionMatchesCallback, &functionMatchList, query, sourceID, targetID);
    return functionMatchList;
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

int SQLiteDisassemblyStorage::ReadFileListCallback(void *arg, int argc, char **argv, char **names)
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

FileList SQLiteDisassemblyStorage::ReadFileList()
{
    FileList fileList;
    ExecuteStatement(ReadFileListCallback, &fileList, "SELECT Type, Filename FROM " FILE_LIST_TABLE);
    return fileList;
}

void SQLiteDisassemblyStorage::InsertMatchMap(int sourceFileID, int targetFileID, va_t sourceAddress, va_t targetAddress, int matchType, int matchRate)
{
    ExecuteStatement(NULL, NULL,
        INSERT_MATCH_MAP_TABLE_STATEMENT,
        sourceFileID,
        targetFileID,
        sourceAddress,
        targetAddress,
        TYPE_MATCH,
        FINGERPRINT_INSIDE_FUNCTION_MATCH,
        0,
        0,
        matchRate,
        0,
        0);

}

char *SQLiteDisassemblyStorage::GetOriginalFilePath(int fileID)
{
    char *originalFilePath;
    ExecuteStatement(ReadRecordStringCallback, &originalFilePath,
        "SELECT OriginalFilePath FROM FileInfo WHERE id = %u", fileID);

    return originalFilePath;
}

void SQLiteDisassemblyStorage::DeleteMatchInfo(int fileID, va_t functionAddress)
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

void SQLiteDisassemblyStorage::DeleteMatches(int srcFileID, int dstFileID)
{
    ExecuteStatement(NULL, NULL, DELETE_MATCH_MAP_TABLE_STATEMENT, srcFileID, dstFileID);
    ExecuteStatement(NULL, NULL, DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT, srcFileID, dstFileID);
}

char *SQLiteDisassemblyStorage::ReadDisasmLine(int fileID, va_t startAddress)
{
    char *disasmLines = NULL;
    ExecuteStatement(ReadRecordStringCallback, &disasmLines, "SELECT DisasmLines FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        fileID, startAddress);
    return disasmLines;
}

int SQLiteDisassemblyStorage::ReadBasicBlockCallback(void *arg, int argc, char **argv, char **names)
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

PBasicBlock SQLiteDisassemblyStorage::ReadBasicBlock(int fileID, va_t address)
{
    PBasicBlock p_basic_block = (PBasicBlock)malloc(sizeof(BasicBlock));
    ExecuteStatement(ReadBasicBlockCallback, p_basic_block,
        "SELECT StartAddress, EndAddress, Flag, FunctionAddress, BlockType, FingerPrint FROM BasicBlock WHERE FileID = %u and StartAddress = %u",
        fileID,
        address);

    return p_basic_block;
}

void SQLiteDisassemblyStorage::UpdateBasicBlock(int fileID, va_t address1, va_t address2)
{
    ExecuteStatement(NULL, NULL, UPDATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_STATEMENT,
        address2, address2 == address1 ? FUNCTION_BLOCK : UNKNOWN_BLOCK, fileID, address1);
}

void SQLiteDisassemblyStorage::AddFileInfo(char *fileType, const char *dbName, int fileID, va_t functionAddress)
{
    ExecuteStatement(NULL, NULL, INSERT_FILE_LIST_TABLE_STATEMENT,
        fileType, dbName, fileID, functionAddress);
}

void SQLiteDisassemblyStorage::AddFunctionMatchInfo(int srcFileID, int targetFileID, FunctionMatchInfo& functionMatchInfo)
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
