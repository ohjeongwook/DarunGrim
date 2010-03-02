#include "DataBaseWriter.h"
#include "sqlite3.h"
#include "DBWrapper.h"

void CreateTables(DBWrapper &db)
{
	db.ExecuteStatement(NULL,NULL,CREATE_ONE_LOCATION_INFO_TABLE_STATEMENT);
	db.ExecuteStatement(NULL,NULL,CREATE_ONE_LOCATION_INFO_TABLE_START_ADDRESS_INDEX_STATEMENT);
	db.ExecuteStatement(NULL,NULL,CREATE_ONE_LOCATION_INFO_TABLE_END_ADDRESS_INDEX_STATEMENT);
	db.ExecuteStatement(NULL,NULL,CREATE_MAP_INFO_TABLE_STATEMENT);
	db.ExecuteStatement(NULL,NULL,CREATE_MAP_INFO_TABLE_INDEX_STATEMENT);
	db.ExecuteStatement(NULL,NULL,CREATE_FILE_INFO_TABLE_STATEMENT);
}

int DatabaseWriterWrapper(DBWrapper *db,BYTE Type,PBYTE Data,DWORD Length)
{
	static int FileID=0;
	bool Status=FALSE;
	static DWORD CurrentAddress=0L;

	switch(Type)
	{
		case ONE_LOCATION_INFO:
			if(sizeof(OneLocationInfo)<=Length)
			{
				POneLocationInfo pOneLocationInfo=(POneLocationInfo)Data;
				TCHAR *FingerprintHexStringBuffer=NULL;
				if(pOneLocationInfo->FingerprintLen>0)
				{
					FingerprintHexStringBuffer=(TCHAR *)malloc(pOneLocationInfo->FingerprintLen*2+10);
					if(FingerprintHexStringBuffer)
					{
						memset(FingerprintHexStringBuffer,0,pOneLocationInfo->FingerprintLen*2+10);
						char tmp_buffer[10];
						for(DWORD i=0;i<pOneLocationInfo->FingerprintLen;i++)
						{
							_snprintf(tmp_buffer,sizeof(tmp_buffer)-1,"%.2x",pOneLocationInfo->Data[pOneLocationInfo->NameLen+pOneLocationInfo->DisasmLinesLen+i]&0xff);
							tmp_buffer[sizeof(tmp_buffer)-1]=NULL;
							strncat(FingerprintHexStringBuffer,tmp_buffer,sizeof(tmp_buffer));
						}
					}
				}
				CurrentAddress=pOneLocationInfo->StartAddress;
				Status=db->ExecuteStatement(NULL,NULL,INSERT_ONE_LOCATION_INFO_TABLE_STATEMENT,
					FileID,
					pOneLocationInfo->StartAddress,
					pOneLocationInfo->EndAddress,
					pOneLocationInfo->Flag,
					pOneLocationInfo->FunctionAddress,
					pOneLocationInfo->BlockType,
					pOneLocationInfo->Data,
					pOneLocationInfo->Data+pOneLocationInfo->NameLen,
					FingerprintHexStringBuffer?FingerprintHexStringBuffer:""
					);
				if(FingerprintHexStringBuffer)
					free(FingerprintHexStringBuffer);
			}
			break;
		case MAP_INFO:
			if(sizeof(MapInfo)<=Length)
			{
				PMapInfo pMapInfo=(PMapInfo)Data;
				Status=db->ExecuteStatement(NULL,NULL,INSERT_MAP_INFO_TABLE_STATEMENT,
					FileID,
					pMapInfo->Type,
					pMapInfo->SrcBlock,
					pMapInfo->SrcBlockEnd,
					pMapInfo->Dst
					);
			}
			break;
		case FILE_INFO:
			if(sizeof(FileInfo)<=Length)
			{
				PFileInfo pFileInfo=(PFileInfo)Data;
				Status=db->ExecuteStatement(NULL,NULL,INSERT_FILE_INFO_TABLE_STATEMENT,
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
				FileID=db->GetLastInsertRowID();
			}
			break;
	}
	Status=TRUE;
	return FileID;
}

