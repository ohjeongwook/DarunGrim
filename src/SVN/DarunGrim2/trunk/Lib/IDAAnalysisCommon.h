#pragma once
#pragma pack(push)
#pragma pack(1)

enum { ONE_LOCATION_INFO,MAP_INFO,FILE_INFO,END_OF_DATA, DISASM_LINES};
//DISASM_LINES,FINGERPRINT_INFO,NAME_INFO
enum {UNKNOWN_BLOCK,FUNCTION_BLOCK};
//MapInfo
//Pushing Map information
enum {CALL,CREF_FROM,CREF_TO,DREF_FROM,DREF_TO,CALLED};

typedef struct _MapInfo_ {
	BYTE Type;
	DWORD SrcBlock;
	DWORD SrcBlockEnd;
	DWORD Dst;
} MapInfo,*PMapInfo;

#define MAP_INFO_TABLE "MapInfo"
#define CREATE_MAP_INFO_TABLE_STATEMENT "CREATE TABLE " MAP_INFO_TABLE" (\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			FileID INTEGER,\n\
			Type INTEGER,\n\
			SrcBlock INTEGER,\n\
			SrcBlockEnd INTEGER,\n\
			Dst INTEGER\n\
		);"
#define CREATE_MAP_INFO_TABLE_INDEX_STATEMENT "CREATE INDEX "MAP_INFO_TABLE"Index ON "MAP_INFO_TABLE" (FileID,SrcBlock,SrcBlockEnd,Dst)"
#define INSERT_MAP_INFO_TABLE_STATEMENT "INSERT INTO  " MAP_INFO_TABLE" (FileID,Type,SrcBlock,SrcBlockEnd,Dst) values ('%u','%u','%u','%u','%u');"

//OneLocationInfo
//Pushing Basic Information on Address

typedef struct _OneLocationInfo_ {
	DWORD StartAddress; //ea_t
	DWORD EndAddress;
	BYTE Flag; //Flag_t
	//func_t get_func(current_addr)
	DWORD FunctionAddress;
	BYTE BlockType; // FUNCTION, UNKNOWN
	int NameLen;
	int DisasmLinesLen;
	int FingerprintLen;
	int CmdArrayLen;
	char Data[0];
} OneLocationInfo,*POneLocationInfo;

#define ONE_LOCATION_INFO_TABLE "OneLocationInfo"
#define CREATE_ONE_LOCATION_INFO_TABLE_STATEMENT "CREATE TABLE " ONE_LOCATION_INFO_TABLE" (\n\
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

#define CREATE_ONE_LOCATION_INFO_TABLE_START_ADDRESS_INDEX_STATEMENT "CREATE INDEX "ONE_LOCATION_INFO_TABLE"StartAddressIndex ON "ONE_LOCATION_INFO_TABLE" (StartAddress)"
#define CREATE_ONE_LOCATION_INFO_TABLE_END_ADDRESS_INDEX_STATEMENT "CREATE INDEX "ONE_LOCATION_INFO_TABLE"EndAddressIndex ON "ONE_LOCATION_INFO_TABLE" (EndAddress)"

//#define CREATE_ONE_LOCATION_INFO_TABLE_INDEX_STATEMENT "CREATE INDEX "ONE_LOCATION_INFO_TABLE"AddressIndex ON "ONE_LOCATION_INFO_TABLE" (FileID,StartAddress,EndAddress,Name,Fingerprint)"
#define INSERT_ONE_LOCATION_INFO_TABLE_STATEMENT "INSERT INTO  " ONE_LOCATION_INFO_TABLE" (FileID,StartAddress,EndAddress,Flag,FunctionAddress,BlockType,Name,DisasmLines,Fingerprint) values ('%u','%u','%u','%u','%u','%u',%Q,%Q,%Q);"
#define UPDATE_ONE_LOCATION_INFO_TABLE_NAME_STATEMENT "UPDATE " ONE_LOCATION_INFO_TABLE" SET Name=%Q WHERE StartAddress='%u';"
#define UPDATE_ONE_LOCATION_INFO_TABLE_FUNCTION_ADDRESS_STATEMENT "UPDATE " ONE_LOCATION_INFO_TABLE" SET FunctionAddress='%u',BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_ONE_LOCATION_INFO_TABLE_BLOCK_TYPE_STATEMENT "UPDATE " ONE_LOCATION_INFO_TABLE" SET BlockType='%d' WHERE FileID='%u' AND StartAddress='%u';"
#define UPDATE_ONE_LOCATION_INFO_TABLE_DISASM_LINES_STATEMENT "UPDATE " ONE_LOCATION_INFO_TABLE" SET DisasmLines=%Q WHERE StartAddress='%u';"
#define UPDATE_ONE_LOCATION_INFO_TABLE_FINGERPRINT_STATEMENT "UPDATE " ONE_LOCATION_INFO_TABLE" SET Fingerprint=%Q WHERE StartAddress='%u';"

typedef struct _FileInfo_ 
{
	TCHAR OriginalFilePath[MAX_PATH+1];
	TCHAR ComputerName[100];
	TCHAR UserName[100];
	TCHAR CompanyName[100];
	TCHAR FileVersion[100];
	TCHAR FileDescription[100];
	TCHAR InternalName[100];
	TCHAR ProductName[100];
	TCHAR ModifiedTime[100];
	TCHAR MD5Sum[100];
} FileInfo,*PFileInfo;

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

#define DREF 0
#define CREF 1
#define FUNCTION 2
#define STACK 3
#define NAME 4
#define DISASM_LINE 5
#define DATA_TYPE 6

#pragma pack(pop)
