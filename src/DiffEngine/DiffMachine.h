#pragma once
#include "OneIDAClientManager.h"
#include "DataStructure.h"
#include <vector>
#include <hash_set>
#include <list>

const enum {DiffMachineFileBinaryFormat,DiffMachineFileSQLiteFormat};

#define MATCH_MAP_TABLE "MatchMap"
#define CREATE_MATCH_MAP_TABLE_STATEMENT "CREATE TABLE " MATCH_MAP_TABLE" (\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			TheSourceFileID INTEGER,\n\
			TheTargetFileID INTEGER,\n\
			TheSourceAddress INTEGER,\n\
			TheTargetAddress INTEGER,\n\
			MatchType INTEGER,\n\
			Type INTEGER,\n\
			SubType INTEGER,\n\
			Status INTEGER,\n\
			MatchRate INTEGER,\n\
			UnpatchedParentAddress INTEGER,\n\
			PatchedParentAddress INTEGER\n\
		);"
#define INSERT_MATCH_MAP_TABLE_STATEMENT "INSERT INTO  "MATCH_MAP_TABLE" (TheSourceFileID,TheTargetFileID,TheSourceAddress,TheTargetAddress,MatchType,Type,SubType,Status,MatchRate,UnpatchedParentAddress,PatchedParentAddress) values ('%u','%u','%u','%u','%u','%u','%u','%u','%u','%u','%u');"
#define DELETE_MATCH_MAP_TABLE_STATEMENT "DELETE FROM "MATCH_MAP_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_MATCH_MAP_TABLE_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"Index ON "MATCH_MAP_TABLE" (TheSourceFileID,TheTargetFileID,TheSourceAddress,TheTargetAddress)"

#define UNIDENTIFIED_BLOCKS_TABLE "UnidentifiedBlocks"
#define CREATE_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "CREATE TABLE "UNIDENTIFIED_BLOCKS_TABLE" (\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			OldFileID INTEGER,\n\
			NewFileID INTEGER,\n\
			Type INTEGER,\n\
			Address INTEGER\n\
		);"
#define INSERT_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT "INSERT INTO  "UNIDENTIFIED_BLOCKS_TABLE" (Type,Address) values ('%u','%u');"

#define FUNCTION_MATCH_INFO_TABLE "FunctionMatchInfo"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "CREATE TABLE " FUNCTION_MATCH_INFO_TABLE" (\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			TheSourceFileID INTEGER,\n\
			TheTargetFileID INTEGER,\n\
			TheSourceAddress INTEGER,\n\
			EndAddress INTEGER,\n\
			TheTargetAddress INTEGER,\n\
			BlockType INTEGER,\n\
			MatchRate INTEGER,\n\
			TheSourceFunctionName TEXT,\n\
			Type INTEGER,\n\
			TheTargetFunctionName TEXT,\n\
			MatchCountForTheSource INTEGER,\n\
			NoneMatchCountForTheSource INTEGER,\n\
			MatchCountWithModificationForTheSource INTEGER,\n\
			MatchCountForTheTarget INTEGER,\n\
			NoneMatchCountForTheTarget INTEGER,\n\
			MatchCountWithModificationForTheTarget INTEGER\n\
		);"
#define INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT "INSERT INTO  " FUNCTION_MATCH_INFO_TABLE" (TheSourceFileID,TheTargetFileID,TheSourceAddress,EndAddress,TheTargetAddress,BlockType,MatchRate,TheSourceFunctionName,Type,TheTargetFunctionName,MatchCountForTheSource,NoneMatchCountForTheSource,MatchCountWithModificationForTheSource,MatchCountForTheTarget,NoneMatchCountForTheTarget,MatchCountWithModificationForTheTarget) values ('%u','%u','%u','%u','%u','%u','%u','%s','%u','%s','%u','%u','%u','%u','%u','%u');"
#define DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "DELETE FROM "FUNCTION_MATCH_INFO_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT "CREATE INDEX "FUNCTION_MATCH_INFO_TABLE"Index ON "FUNCTION_MATCH_INFO_TABLE" (TheSourceFileID,TheTargetFileID,TheSourceAddress,TheTargetAddress)"

typedef struct _AnalysisResult_ {
	multimap <DWORD,MatchData> MatchMap;
	hash_map <DWORD,DWORD> ReverseAddressMap;
} AnalysisResult;

class DiffMachine
{
private:
	DBWrapper *m_InputDB;
	int m_TheSourceFileID;
	int m_TheTargetFileID;

	multimap <DWORD,DWORD> *FunctionMembersMapForTheSource;
	multimap <DWORD,DWORD> *FunctionMembersMapForTheTarget;
	multimap <DWORD,DWORD> *AddressToFunctionMapForTheSource;
	multimap <DWORD,DWORD> *AddressToFunctionMapForTheTarget;

	SOCKET SocketForTheSource;
	SOCKET SocketForeTheTarget;
	OneIDAClientManager *TheSource;
	OneIDAClientManager *TheTarget;
	AnalysisResult *DiffResults;

	int GetFingerPrintMatchRate(unsigned char* unpatched_finger_print,unsigned char* patched_finger_print);

	void RemoveDuplicates();
	void RevokeTreeMatchMapIterInfo(DWORD address,DWORD match_address);
	void GenerateFunctionMatchInfo();

	hash_set <DWORD> TheSourceUnidentifedBlockHash;
	hash_set <DWORD> TheTargetUnidentifedBlockHash;

	vector <FunctionMatchInfo> FunctionMatchInfoList;
	vector <FunctionMatchInfo> ReverseFunctionMatchInfoList;
public:
	DiffMachine(OneIDAClientManager *the_source=NULL,OneIDAClientManager *the_target=NULL);
	void SetOneIDAClientManagers(OneIDAClientManager *the_source,OneIDAClientManager *the_target);
	OneIDAClientManager *GetTheSource();
	OneIDAClientManager *GetTheTarget();
	void DumpMatchMapIterInfo(const char *prefix,multimap <DWORD, MatchData>::iterator match_map_iter);
	DWORD DumpFunctionMatchInfo(int index,DWORD address);
	void DiffMachine::GetMatchStatistics(
		DWORD address,
		OneIDAClientManager *ClientManager,
		int index,
		int *p_found_match_number,
		int *p_found_match_with_difference_number,
		int *p_not_found_match_number
		);
	int GetMatchRate(DWORD unpatched_address,DWORD patched_address);

	MatchData *GetMatchData(int index,DWORD address);
	void AppendToMatchMap(multimap <DWORD,MatchData> *pBaseMap,multimap <DWORD,MatchData> *pTemporaryMap);

	void DoFingerPrintMatch(multimap <DWORD,MatchData> *pTemporaryMap);
	void DoIsomorphMatch(multimap <DWORD,MatchData> *pTemporaryMap);
	void DoFunctionMatch(multimap <DWORD,MatchData> *pTemporaryMap,multimap <DWORD,MatchData> *pTargetTemporaryMap);
	void DoFingerPrintMatchInsideFunction(multimap <DWORD,MatchData> *pTemporaryMap,DWORD SourceFunctionAddress,list <DWORD> &SourceBlockAddresses,DWORD TargetFunctionAddress,list <DWORD> &TargetBlockAddresses);
	void PurgeFingerprintHashMap(multimap <DWORD,MatchData> *pTemporaryMap);
	void ShowDiffMap(DWORD unpatched_address,DWORD patched_address);
	void PrintMatchMapInfo();
	bool Analyze();
	void AnalyzeFunctionSanity();
	DWORD GetMatchAddr(int index,DWORD address);

	int GetFunctionMatchInfoCount();
	FunctionMatchInfo GetFunctionMatchInfo(int i);

	int GetUnidentifiedBlockCount(int index);
	CodeBlock GetUnidentifiedBlock(int index,int i);
	BOOL IsInUnidentifiedBlockHash(int index,DWORD address);
	BOOL Save(char *DataFile,BYTE Type=DiffMachineFileSQLiteFormat,DWORD Offset=0L,DWORD dwMoveMethod=FILE_BEGIN,hash_set <DWORD> *pTheSourceSelectedAddresses=NULL,hash_set <DWORD> *pTheTargetSelectedAddresses=NULL);
	BOOL Retrieve(char *DataFile,BYTE Type=DiffMachineFileSQLiteFormat,DWORD Offset=0L,DWORD Length=0L);
	BOOL Save(DBWrapper& OutputDB,hash_set <DWORD> *pTheSourceSelectedAddresses=NULL,hash_set <DWORD> *pTheTargetSelectedAddresses=NULL);
	BOOL Retrieve(DBWrapper& InputDB,BOOL bRetrieveDataForAnalysis=FALSE,int TheSourceFileID=1,int TheTargetFileID=2,BOOL bLoadMatchMapToMemory=FALSE);
	char *GetMatchTypeStr(int Type);

	void ExecuteOnFunctionMatchInfoList(void (Callback(FunctionMatchInfo &Data,PVOID Context)),PVOID Context)
	{
		for(vector <FunctionMatchInfo>::iterator iter=FunctionMatchInfoList.begin();iter!=FunctionMatchInfoList.end();iter++)
		{
			Callback(*iter,Context);
		}
	}
	
	void ExecuteOnTheSourceUnidentifedBlockHash(void (Callback(DWORD Data,PVOID Context)),PVOID Context)
	{
		for(hash_set <DWORD>::iterator iter=TheSourceUnidentifedBlockHash.begin();iter!=TheSourceUnidentifedBlockHash.end();iter++)
		{
			Callback(*iter,Context);
		}
	}
	void ExecuteOnTheTargetUnidentifedBlockHash(void (Callback(DWORD Data,PVOID Context)),PVOID Context)
	{
		for(hash_set <DWORD>::iterator iter=TheTargetUnidentifedBlockHash.begin();iter!=TheTargetUnidentifedBlockHash.end();iter++)
		{
			Callback(*iter,Context);
		}
	}
};
