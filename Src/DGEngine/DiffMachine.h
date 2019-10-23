#pragma once
#include <vector>
#include <unordered_set>
#include <list>

#include "Common.h"
#include "IDAController.h"
#include "DataStructure.h"
#include "LogOperation.h"

const enum {DiffMachineFileSQLiteFormat};

enum {TYPE_MATCH, TYPE_REVERSE_MATCH, TYPE_BEFORE_UNIDENTIFIED_BLOCK, TYPE_AFTER_UNIDENTIFIED_BLOCK};

#undef TEST_MATCHMAP

#ifdef TEST_MATCHMAP
class MATCHMAP
{
public:
	multimap <va_t, MatchData> MatchMap;

	void insert(MatchMap_Pair d)
	{
		MatchMap.insert(d);
	}

	multimap <va_t, MatchData>::iterator erase(multimap <va_t, MatchData>::iterator d)
	{
		return MatchMap.erase(d);
	}

	multimap <va_t, MatchData>::iterator find(va_t d)
	{
		return MatchMap.find(d);
	}

	multimap <va_t, MatchData>::iterator begin()
	{
		return MatchMap.begin();
	}

	multimap <va_t, MatchData>::iterator end()
	{
		return MatchMap.end();
	}

	int size()
	{
		return MatchMap.size();
	}

	int count(va_t d)
	{
		return MatchMap.count(d);
	}

	void clear()
	{
		return MatchMap.clear();
	}
};

#else
typedef multimap <va_t, MatchData> MATCHMAP;
#endif

class AnalysisResult;

#define DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING 1

class BREAKPOINTS
{
public:
	unordered_set<va_t> SourceFunctionMap;
	unordered_set<va_t> SourceAddressMap;

	unordered_set<va_t> TargetFunctionMap;
	unordered_set<va_t> TargetAddressMap;
};

typedef struct
{
	va_t Source;
	va_t Target;
	int MatchRate;
	int IndexDiff;
} MatchRateInfo;

class DumpAddressChecker
{
private:
	unordered_set <va_t> SrcDumpAddresses;
	unordered_set <va_t> TargetDumpAddresses;

public:
	void AddSrcDumpAddress(va_t address);
	void AddTargetDumpAddress(va_t address);
	bool IsDumpPair(va_t src, va_t target);
	void DumpMatchInfo(va_t src, va_t target, int match_rate, const char *format, ...);
};

class DiffMachine
{
private:
	int DebugFlag;
	SOCKET SocketForTheSource;
	SOCKET SocketForeTheTarget;

	int GetFingerPrintMatchRate( unsigned char* unpatched_finger_print, unsigned char* patched_finger_print );

	void RemoveDuplicates();
	void RevokeTreeMatchMapIterInfo(va_t address, va_t match_address );
	void GenerateFunctionMatchInfo();

	BOOL DeleteMatchInfo(DisassemblyStorage& disassemblyStorage );

	unordered_set <va_t> TheSourceUnidentifedBlockHash;
	unordered_set <va_t> TheTargetUnidentifedBlockHash;

	vector <FunctionMatchInfo> FunctionMatchList;
	vector <FunctionMatchInfo> ReverseFunctionMatchList;

	//Algorithms
	void DoFingerPrintMatch(MATCHMAP *pTemporaryMap);
	void DoFingerPrintMatchInsideFunction(va_t SourceFunctionAddress, list <va_t> &SourceBlockAddresses, va_t TargetFunctionAddress, list <va_t> &TargetBlockAddresses);
	void PurgeFingerprintHashMap(MATCHMAP *pTemporaryMap);

	void DoIsomorphMatch(MATCHMAP *pTemporaryMap);
	void DoFunctionMatch(MATCHMAP *pTargetTemporaryMap);
	bool DoFunctionLevelMatchOptimizing();

	MatchRateInfo *GetMatchRateInfoArray(va_t source_address, va_t target_address, int type, int &MatchRateInfoCount);
	DumpAddressChecker *pDumpAddressChecker;

	void FreeMatchMapList(vector<MatchData*> *pMatchMapList);

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
	void DumpMatchMapIterInfo( const char *prefix, multimap <va_t,  MatchData>::iterator match_map_iter );
	va_t DumpFunctionMatchInfo( int index, va_t address );
	void GetMatchStatistics(va_t address, int index, int &found_match_number, int &found_match_with_difference_number, int &not_found_match_number, float &matchrate);
	int GetMatchRate(va_t unpatched_address, va_t patched_address );

	void RemoveMatchData(va_t source_address, va_t target_address);
	void CleanUpMatchDataList(vector<MatchData *> match_data_list);
	vector<MatchData *> *GetMatchData(int index, va_t address, BOOL erase = FALSE);
	void AppendToMatchMap(MATCHMAP *pBaseMap, MATCHMAP *pTemporaryMap);


	void ShowDiffMap(va_t unpatched_address, va_t patched_address );
	void PrintMatchMapInfo();

	void TestFunctionMatchRate( int index, va_t Address );
	void RetrieveNonMatchingMembers( int index, va_t FunctionAddress, list <va_t>& Members );
	bool TestAnalysis();
	bool Analyze();
	void AnalyzeFunctionSanity();
	va_t GetMatchAddr( int index, va_t address );

	int GetFunctionMatchInfoCount();
	FunctionMatchInfo GetFunctionMatchInfo( int i );

	int GetUnidentifiedBlockCount( int index );
	CodeBlock GetUnidentifiedBlock( int index, int i );
	BOOL IsInUnidentifiedBlockHash( int index, va_t address );

	BOOL Save( char *DataFile, BYTE Type=DiffMachineFileSQLiteFormat, DWORD Offset=0L, DWORD dwMoveMethod=FILE_BEGIN, unordered_set <va_t> *pTheSourceSelectedAddresses=NULL, unordered_set <DWORD> *pTheTargetSelectedAddresses=NULL );
	BOOL Save(DisassemblyStorage& disassemblyStorage, unordered_set <va_t> *pTheSourceSelectedAddresses=NULL, unordered_set <DWORD> *pTheTargetSelectedAddresses=NULL );
	
private:
	BOOL bRetrieveDataForAnalysis;

public:
	void SetRetrieveDataForAnalysis(BOOL newRetrieveDataForAnalysis)
	{
		bRetrieveDataForAnalysis = newRetrieveDataForAnalysis;
	}

	const char *GetMatchTypeStr( int Type );

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
	va_t SourceFunctionAddress;

	string TargetDBName;
	int TargetID;
	va_t TargetFunctionAddress;

    DisassemblyStorage *m_diffDisassemblyStorage;
    DisassemblyStorage *m_sourceDisassemblyStorage;
    DisassemblyStorage *m_targetDisassemblyStorage;

	IDAController *SourceController;
	IDAController *TargetController;
	AnalysisResult *DiffResults;

	BOOL _Load();

public:

	void SetSource(const char *db_filename, DWORD id = 1, va_t function_address = 0)
	{
		SourceDBName = db_filename;
		SourceID = id;
		SourceFunctionAddress = function_address;
	}

	void SetTarget(const char *db_filename, DWORD id = 1, va_t function_address = 0)
	{
		TargetDBName = db_filename;
		TargetID = id;
		TargetFunctionAddress = function_address;
	}

	void SetSource(DisassemblyStorage *disassemblyStorage, DWORD id = 1, va_t function_address = 0)
	{
		m_sourceDisassemblyStorage = disassemblyStorage;
		SourceID = id;
		SourceFunctionAddress = function_address;
	}

	void SetTarget(DisassemblyStorage *disassemblyStorage, DWORD id = 1, va_t function_address = 0)
	{
		m_targetDisassemblyStorage = disassemblyStorage;
		TargetID = id;
		TargetFunctionAddress = function_address;
	}

	void SetTargetFunctions(va_t ParamSourceFunctionAddress, va_t ParamTargetFunctionAddress)
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

