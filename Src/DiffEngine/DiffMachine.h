#pragma once
#include <vector>
#include <hash_set>
#include <list>

#include "Common.h"
#include "IDAController.h"
#include "DataStructure.h"
#include "LogOperation.h"

const enum {DiffMachineFileSQLiteFormat};

#define MATCH_MAP_TABLE "MatchMap"
#define CREATE_MATCH_MAP_TABLE_STATEMENT "CREATE TABLE " MATCH_MAP_TABLE" ( \n\
			id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
			TheSourceFileID INTEGER, \n\
			TheTargetFileID INTEGER, \n\
			TheSourceAddress INTEGER, \n\
			TheTargetAddress INTEGER, \n\
			MatchType INTEGER, \n\
			Type INTEGER, \n\
			SubType INTEGER, \n\
			Status INTEGER, \n\
			MatchRate INTEGER, \n\
			UnpatchedParentAddress INTEGER, \n\
			PatchedParentAddress INTEGER\n\
		 );"

#define INSERT_MATCH_MAP_TABLE_STATEMENT "INSERT INTO  "MATCH_MAP_TABLE" ( TheSourceFileID, TheTargetFileID, TheSourceAddress, TheTargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress ) values ( '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u' );"
#define DELETE_MATCH_MAP_TABLE_STATEMENT "DELETE FROM "MATCH_MAP_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"TheSourceAddressIndex ON "MATCH_MAP_TABLE" ( TheSourceAddress )"
#define CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT "CREATE INDEX "MATCH_MAP_TABLE"TheTargetAddressIndex ON "MATCH_MAP_TABLE" ( TheTargetAddress )"

#define FILE_LIST_TABLE "FileList"
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

#define FUNCTION_MATCH_INFO_TABLE "FunctionMatchInfo"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "CREATE TABLE " FUNCTION_MATCH_INFO_TABLE" ( \n\
			id INTEGER PRIMARY KEY AUTOINCREMENT, \n\
			TheSourceFileID INTEGER, \n\
			TheTargetFileID INTEGER, \n\
			TheSourceAddress INTEGER, \n\
			EndAddress INTEGER, \n\
			TheTargetAddress INTEGER, \n\
			BlockType INTEGER, \n\
			MatchRate INTEGER, \n\
			TheSourceFunctionName TEXT, \n\
			Type INTEGER, \n\
			TheTargetFunctionName TEXT, \n\
			MatchCountForTheSource INTEGER, \n\
			NoneMatchCountForTheSource INTEGER, \n\
			MatchCountWithModificationForTheSource INTEGER, \n\
			MatchCountForTheTarget INTEGER, \n\
			NoneMatchCountForTheTarget INTEGER, \n\
			MatchCountWithModificationForTheTarget INTEGER, \n\
			SecurityImplicationsScore INTEGER \n\
		 );"
#define INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT "INSERT INTO  " FUNCTION_MATCH_INFO_TABLE" ( TheSourceFileID, TheTargetFileID, TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget ) values ( '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%s', '%u', '%s', '%u', '%u', '%u', '%u', '%u', '%u' );"
#define DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT "DELETE FROM "FUNCTION_MATCH_INFO_TABLE" WHERE TheSourceFileID=%u and TheTargetFileID=%u"
#define CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT "CREATE INDEX "FUNCTION_MATCH_INFO_TABLE"Index ON "FUNCTION_MATCH_INFO_TABLE" ( TheSourceFileID, TheTargetFileID, TheSourceAddress, TheTargetAddress )"

enum {TYPE_MATCH, TYPE_REVERSE_MATCH, TYPE_BEFORE_UNIDENTIFIED_BLOCK, TYPE_AFTER_UNIDENTIFIED_BLOCK};

#undef TEST_MATCHMAP

#ifdef TEST_MATCHMAP
class MATCHMAP
{
public:
	multimap <DWORD, MatchData> MatchMap;

	void insert(MatchMap_Pair d)
	{
		if (d.first == 0x31ab6d92)
		{
			printf("found interesting part");
		}

		MatchMap.insert(d);
	}

	multimap <DWORD, MatchData>::iterator erase(multimap <DWORD, MatchData>::iterator d)
	{
		if ((*d).first == 0x31ab6d92)
		{
			printf("found interesting part");
		}

		return MatchMap.erase(d);
	}

	multimap <DWORD, MatchData>::iterator find(DWORD d)
	{
		return MatchMap.find(d);
	}

	multimap <DWORD, MatchData>::iterator begin()
	{
		return MatchMap.begin();
	}

	multimap <DWORD, MatchData>::iterator end()
	{
		return MatchMap.end();
	}

	int size()
	{
		return MatchMap.size();
	}

	int count(DWORD d)
	{
		return MatchMap.count(d);
	}

	void clear()
	{
		return MatchMap.clear();
	}
};

#else
typedef multimap <DWORD, MatchData> MATCHMAP;
#endif

class AnalysisResult;

#define DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING 1

class BREAKPOINTS
{
public:
	hash_set<DWORD> SourceFunctionMap;
	hash_set<DWORD> SourceAddressMap;

	hash_set<DWORD> TargetFunctionMap;
	hash_set<DWORD> TargetAddressMap;
};

typedef struct
{
	DWORD Source;
	DWORD Target;
	int MatchRate;
	int IndexDiff;
} MatchRateInfo;

class DumpAddressChecker
{
private:
	hash_set <DWORD> SrcDumpAddresses;
	hash_set <DWORD> TargetDumpAddresses;

public:
	void AddSrcDumpAddress(DWORD address);
	void AddTargetDumpAddress(DWORD address);
	bool IsDumpPair(DWORD src, DWORD target);
	void DumpMatchInfo(DWORD src, DWORD target, int match_rate, const char *format, ...);
};

class DiffMachine
{
private:
	int DebugFlag;
	SOCKET SocketForTheSource;
	SOCKET SocketForeTheTarget;

	int GetFingerPrintMatchRate( unsigned char* unpatched_finger_print, unsigned char* patched_finger_print );

	void RemoveDuplicates();
	void RevokeTreeMatchMapIterInfo( DWORD address, DWORD match_address );
	void GenerateFunctionMatchInfo();

	BOOL DeleteMatchInfo(DisassemblyStorage& disassemblyStorage );

	hash_set <DWORD> TheSourceUnidentifedBlockHash;
	hash_set <DWORD> TheTargetUnidentifedBlockHash;

	vector <FunctionMatchInfo> FunctionMatchList;
	vector <FunctionMatchInfo> ReverseFunctionMatchList;

	//Algorithms
	void DoFingerPrintMatch(MATCHMAP *pTemporaryMap);
	void DoFingerPrintMatchInsideFunction(DWORD SourceFunctionAddress, list <DWORD> &SourceBlockAddresses, DWORD TargetFunctionAddress, list <DWORD> &TargetBlockAddresses);
	void PurgeFingerprintHashMap(MATCHMAP *pTemporaryMap);

	void DoIsomorphMatch(MATCHMAP *pTemporaryMap);
	void DoFunctionMatch(MATCHMAP *pTargetTemporaryMap);
	bool DoFunctionLevelMatchOptimizing();

	MatchRateInfo *GetMatchRateInfoArray(DWORD source_address, DWORD target_address, int type, int &MatchRateInfoCount);
	DumpAddressChecker *pDumpAddressChecker;

public:
	DiffMachine( IDAController *the_source=NULL, IDAController *the_target=NULL );
	~DiffMachine();
	void ClearFunctionMatchList();

	void SetDumpAddressChecker(DumpAddressChecker *p_dump_address_checker)
	{
		pDumpAddressChecker = p_dump_address_checker;
	}

	void SetSource(IDAController *NewSource)
	{
		SourceController = NewSource;
	}

	void SetTarget(IDAController *NewTarget)
	{
		TargetController = NewTarget;
	}

	IDAController *GetSourceController();
	IDAController *GetTargetController();
	void DumpMatchMapIterInfo( const char *prefix, multimap <DWORD,  MatchData>::iterator match_map_iter );
	DWORD DumpFunctionMatchInfo( int index, DWORD address );
	void DiffMachine::GetMatchStatistics( 
		DWORD address, 
		int index, 
		int &found_match_number, 
		int &found_match_with_difference_number,
		int &not_found_match_number,
		float &matchrate
	);
	int GetMatchRate( DWORD unpatched_address, DWORD patched_address );

	void RemoveMatchData(DWORD source_address, DWORD target_address);
	void CleanUpMatchDataList(vector<MatchData *> match_data_list);
	vector<MatchData *> GetMatchData(int index, DWORD address, BOOL erase = FALSE);
	void AppendToMatchMap(MATCHMAP *pBaseMap, MATCHMAP *pTemporaryMap);


	void ShowDiffMap( DWORD unpatched_address, DWORD patched_address );
	void PrintMatchMapInfo();

	void TestFunctionMatchRate( int index, DWORD Address );
	void RetrieveNonMatchingMembers( int index, DWORD FunctionAddress, list <DWORD>& Members );
	bool TestAnalysis();
	bool Analyze();
	void AnalyzeFunctionSanity();
	DWORD GetMatchAddr( int index, DWORD address );

	int GetFunctionMatchInfoCount();
	FunctionMatchInfo GetFunctionMatchInfo( int i );

	int GetUnidentifiedBlockCount( int index );
	CodeBlock GetUnidentifiedBlock( int index, int i );
	BOOL IsInUnidentifiedBlockHash( int index, DWORD address );

	BOOL Save( char *DataFile, BYTE Type=DiffMachineFileSQLiteFormat, DWORD Offset=0L, DWORD dwMoveMethod=FILE_BEGIN, hash_set <DWORD> *pTheSourceSelectedAddresses=NULL, hash_set <DWORD> *pTheTargetSelectedAddresses=NULL );
	BOOL Save(DisassemblyStorage& disassemblyStorage, hash_set <DWORD> *pTheSourceSelectedAddresses=NULL, hash_set <DWORD> *pTheTargetSelectedAddresses=NULL );
	
private:
	BOOL bRetrieveDataForAnalysis;

public:
	void SetRetrieveDataForAnalysis(BOOL newRetrieveDataForAnalysis)
	{
		bRetrieveDataForAnalysis = newRetrieveDataForAnalysis;
	}

	char *GetMatchTypeStr( int Type );

private:
	bool LoadDiffResults;
	bool LoadIDAController;
public:
	void SetLoadDiffResults(bool NewLoadDiffResults)
	{
		LoadDiffResults = NewLoadDiffResults;
	}

	void SetLoadIDAController(bool NewLoadIDAController)
	{
		LoadIDAController = NewLoadIDAController;
	}

private:
	string SourceDBName;
	int SourceID;
	DWORD SourceFunctionAddress;

	string TargetDBName;
	int TargetID;
	DWORD TargetFunctionAddress;

    DisassemblyStorage *m_diffDisassemblyStorage;
    DisassemblyStorage *m_sourceDisassemblyStorage;
    DisassemblyStorage *m_targetDisassemblyStorage;

	IDAController *SourceController;
	IDAController *TargetController;
	AnalysisResult *DiffResults;

	BOOL _Load();

public:

	void SetSource(const char *db_filename, DWORD id = 1, DWORD function_address = 0)
	{
		SourceDBName = db_filename;
		SourceID = id;
		SourceFunctionAddress = function_address;
	}

	void SetTarget(const char *db_filename, DWORD id = 1, DWORD function_address = 0)
	{
		TargetDBName = db_filename;
		TargetID = id;
		TargetFunctionAddress = function_address;
	}

	void SetSource(DisassemblyStorage *disassemblyStorage, DWORD id = 1, DWORD function_address = 0)
	{
		m_sourceDisassemblyStorage = disassemblyStorage;
		SourceID = id;
		SourceFunctionAddress = function_address;
	}

	void SetTarget(DisassemblyStorage *disassemblyStorage, DWORD id = 1, DWORD function_address = 0)
	{
		m_targetDisassemblyStorage = disassemblyStorage;
		TargetID = id;
		TargetFunctionAddress = function_address;
	}

	void SetTargetFunctions(DWORD ParamSourceFunctionAddress, DWORD ParamTargetFunctionAddress)
	{
		SourceFunctionAddress = ParamSourceFunctionAddress;
		TargetFunctionAddress = ParamTargetFunctionAddress;
	}

	BOOL Create(const char *DiffDBFilename);
	BOOL Load(const char *DiffDBFilename);
	BOOL Load(DisassemblyStorage *disassemblyStorage);

	bool ShowFullMatched;
	bool ShowNonMatched;


	BREAKPOINTS ShowUnidentifiedAndModifiedBlocks();
};

