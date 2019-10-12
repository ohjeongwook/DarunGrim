#pragma once
#include <stdio.h>
#include "sqlite3.h"
#include "DisassemblyStorage.h"
#include <string>
using namespace std;

DisassemblyStorage::DisassemblyStorage( const char *DatabaseName)
{
	db=NULL;
	if( DatabaseName )
		CreateDatabase( DatabaseName );
}

DisassemblyStorage::~DisassemblyStorage()
{
	CloseDatabase();
}

void DisassemblyStorage::SetFileInfo(FileInfo *p_file_info)
{

}

void DisassemblyStorage::EndAnalysis()
{
}

void DisassemblyStorage::AddBasicBlock(PBasicBlock p_basic_block)
{
}

void DisassemblyStorage::AddMapInfo(PMapInfo p_map_info)
{
}

void DisassemblyStorage::CreateTables()
{
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_START_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_BASIC_BLOCK_TABLE_END_ADDRESS_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
    ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);
}

int DisassemblyStorage::DatabaseWriterWrapper(BYTE Type, PBYTE Data, DWORD Length)
{
    static int FileID = 0;
    bool Status = FALSE;
    static DWORD CurrentAddress = 0L;

    switch (Type)
    {
    case BASIC_BLOCK:
        if (sizeof(BasicBlock) <= Length)
        {
            PBasicBlock pBasicBlock = (PBasicBlock)Data;
            char *FingerprintHexStringBuffer = NULL;
            if (pBasicBlock->FingerprintLen > 0)
            {
                FingerprintHexStringBuffer = (char *)malloc(pBasicBlock->FingerprintLen * 2 + 10);
                if (FingerprintHexStringBuffer)
                {
                    memset(FingerprintHexStringBuffer, 0, pBasicBlock->FingerprintLen * 2 + 10);
                    char tmp_buffer[10];
                    for (int i = 0; i < pBasicBlock->FingerprintLen; i++)
                    {
                        _snprintf(tmp_buffer, sizeof(tmp_buffer) - 1, "%.2x", pBasicBlock->Data[pBasicBlock->NameLen + pBasicBlock->DisasmLinesLen + i] & 0xff);
                        tmp_buffer[sizeof(tmp_buffer) - 1] = NULL;
                        strncat(FingerprintHexStringBuffer, tmp_buffer, sizeof(tmp_buffer));
                    }
                }
            }

            CurrentAddress = pBasicBlock->StartAddress;
            Status = ExecuteStatement(NULL, NULL, INSERT_BASIC_BLOCK_TABLE_STATEMENT,
                FileID,
                pBasicBlock->StartAddress,
                pBasicBlock->EndAddress,
                pBasicBlock->Flag,
                pBasicBlock->FunctionAddress,
                pBasicBlock->BlockType,
                pBasicBlock->Data,
                pBasicBlock->Data + pBasicBlock->NameLen,
                FingerprintHexStringBuffer ? FingerprintHexStringBuffer : ""
            );

            if (FingerprintHexStringBuffer)
                free(FingerprintHexStringBuffer);
        }
        break;

    case MAP_INFO:
        if (sizeof(MapInfo) <= Length)
        {
            PMapInfo pMapInfo = (PMapInfo)Data;
            Status = ExecuteStatement(NULL, NULL, INSERT_MAP_INFO_TABLE_STATEMENT,
                FileID,
                pMapInfo->Type,
                pMapInfo->SrcBlock,
                pMapInfo->SrcBlockEnd,
                pMapInfo->Dst
            );
        }
        break;

    case FILE_INFO:
        if (sizeof(FileInfo) <= Length)
        {
            PFileInfo pFileInfo = (PFileInfo)Data;
            Status = ExecuteStatement(NULL, NULL, INSERT_FILE_INFO_TABLE_STATEMENT,
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
            FileID = GetLastInsertRowID();
        }
        break;

    }
    Status = TRUE;
    return FileID;
}

bool DisassemblyStorage::Open( char *DatabaseName )
{
	m_DatabaseName = DatabaseName;
	return CreateDatabase( DatabaseName );
}

bool DisassemblyStorage::CreateDatabase(const char *DatabaseName)
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

const char *DisassemblyStorage::GetDatabaseName()
{
	return m_DatabaseName.c_str();
}

void DisassemblyStorage::CloseDatabase()
{
	//Close Database
	if(db)
	{
		sqlite3_close(db);
		db=NULL;
	}
}

int DisassemblyStorage::BeginTransaction()
{
	return ExecuteStatement(NULL,NULL,"BEGIN TRANSACTION");
}

int DisassemblyStorage::EndTransaction()
{
	return ExecuteStatement(NULL,NULL,"COMMIT");
}

int DisassemblyStorage::GetLastInsertRowID()
{
	return (int)sqlite3_last_insert_rowid(db);
}

int DisassemblyStorage::ExecuteStatement( sqlite3_callback callback, void *context, char *format, ... )
{
	int debug=0;

	if(db)
	{
		int rc = 0;
		char *statement_buffer=NULL;
		char *zErrMsg=0;

		va_list args;
		va_start(args,format);
#ifdef USE_VSNPRINTF
		int statement_buffer_len=0;

		while(1)
		{
			statement_buffer_len+=1024;
			statement_buffer=(char *)malloc(statement_buffer_len);
			memset(statement_buffer,0,statement_buffer_len);
			if(statement_buffer && _vsnprintf(statement_buffer,statement_buffer_len,format,args)!=-1)
			{
				free(statement_buffer);
				break;
			}

			if(!statement_buffer)
				break;
			free(statement_buffer);
		}
#else
		statement_buffer=sqlite3_vmprintf(format,args);
#endif
		va_end(args);

		if(debug>1)
		{
#ifdef IDA_PLUGIN			
			msg("Executing [%s]\n",statement_buffer);
#else
			printf("Executing [%s]\n",statement_buffer);
#endif
		}

		if(statement_buffer)
		{
			rc=sqlite3_exec(db, statement_buffer,callback, context, &zErrMsg );

			if(rc!=SQLITE_OK)
			{
				if(debug>0)
				{
#ifdef IDA_PLUGIN				
					msg("SQL error: [%s] [%s]\n",statement_buffer,zErrMsg);
#else
					printf("SQL error: [%s] [%s]\n",statement_buffer,zErrMsg);
#endif
				}
			}
#ifdef USE_VSNPRINTF
			free( statement_buffer );
#else
			sqlite3_free( statement_buffer );
#endif
		}

		return rc;
	}
	return SQLITE_ERROR;
}

int DisassemblyStorage::display_callback(void *NotUsed, int argc, char **argv, char **azColName)
{
	int i;
	for(i=0; i<argc; i++){
		//msg("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	return 0;
}

int DisassemblyStorage::ReadRecordIntegerCallback(void *arg,int argc,char **argv,char **names)
{
#if DEBUG_LEVEL > 2
	printf("%s: arg=%x %d\n",__FUNCTION__,arg,argc);
	for(int i=0;i<argc;i++)
	{
		printf("	[%d] %s=%s\n",i,names[i],argv[i]);
	}
#endif
	*(int *)arg=atoi(argv[0]);
	return 0;
}

int DisassemblyStorage::ReadRecordStringCallback(void *arg,int argc,char **argv,char **names)
{
#if DEBUG_LEVEL > 2
	printf("%s: arg=%x %d\n",__FUNCTION__,arg,argc);
	for(int i=0;i<argc;i++)
	{
		printf("	[%d] %s=%s\n",i,names[i],argv[i]);
	}
#endif
	*(char **)arg=_strdup(argv[0]);
	return 0;
}
