#pragma once
#include <vector>
#include <unordered_set>
#include <list>

#include "Common.h"
#include "IDASession.h"
#include "LogOperation.h"
#include "MatchResults.h"
#include "DiffAlgorithms.h"

class IDASessions
{
private:
    int DebugFlag;
    SOCKET SocketForTheSource;
    SOCKET SocketForeTheTarget;
	DiffAlgorithms *pDiffAlgorithms;
	BOOL bRetrieveDataForAnalysis;
    MatchResults *pMatchResults;
    DumpAddressChecker *pDumpAddressChecker;
    vector <FunctionMatchInfo> *pFunctionMatchInfoList;

    unordered_set <va_t> SourceUnidentifedBlockHash;
    unordered_set <va_t> TargetUnidentifedBlockHash;

	bool ShowFullMatched;
	bool ShowNonMatched;

	bool LoadDiffResults;
	bool LoadIDAController;

	string SourceDBName;
	int SourceID;
	va_t SourceFunctionAddress;

	string TargetDBName;
	int TargetID;
	va_t TargetFunctionAddress;

	DisassemblyStorage *m_diffDisassemblyStorage;
	DisassemblyStorage *m_sourceDisassemblyStorage;
	DisassemblyStorage *m_targetDisassemblyStorage;

	IDASession *SourceIDASession;
	IDASession *TargetIDASession;

	BOOL _Load();

public:
    IDASessions(IDASession *the_source = NULL, IDASession *the_target = NULL);
    ~IDASessions();
    void ClearFunctionMatchList();

    void SetDumpAddressChecker(DumpAddressChecker *p_dump_address_checker)
    {
        pDumpAddressChecker = p_dump_address_checker;
    }

    void SetSource(IDASession *NewSource)
    {
        SourceIDASession = NewSource;
    }

    void SetTarget(IDASession *NewTarget)
    {
        TargetIDASession = NewTarget;
    }

    IDASession *GetSourceIDASession();
    IDASession *GetTargetIDASession();
    va_t DumpFunctionMatchInfo(int index, va_t address);
    void GetMatchStatistics(va_t address, int index, int& found_match_number, int& found_match_with_difference_number, int& not_found_match_number, float& matchrate);
    int GetMatchRate(va_t unpatched_address, va_t patched_address);

    void RemoveMatchData(va_t source_address, va_t target_address);
    void CleanUpMatchDataList(vector<MatchData*> match_data_list);
    MatchMapList *GetMatchData(int index, va_t address, BOOL erase = FALSE);
    void AppendToMatchMap(MATCHMAP *pBaseMap, MATCHMAP *pTemporaryMap);
    void ShowDiffMap(va_t unpatched_address, va_t patched_address);

    void TestFunctionMatchRate(int index, va_t Address);
    void RetrieveNonMatchingMembers(int index, va_t FunctionAddress, list <va_t>& Members);
    bool TestAnalysis();
    MATCHMAP *DoFunctionLevelMatchOptimizing(vector <FunctionMatchInfo> *pFunctionMatchInfoList);
    bool Analyze();
    void AnalyzeFunctionSanity();
    va_t GetMatchAddr(int index, va_t address);

    int GetFunctionMatchInfoCount();
    FunctionMatchInfo GetFunctionMatchInfo(int i);

    int GetUnidentifiedBlockCount(int index);
    CodeBlock GetUnidentifiedBlock(int index, int i);
    BOOL IsInUnidentifiedBlockHash(int index, va_t address);

    BOOL Save(DisassemblyStorage& disassemblyStorage, unordered_set <va_t> *pTheSourceSelectedAddresses = NULL, unordered_set <va_t> *pTheTargetSelectedAddresses = NULL);

    void SetRetrieveDataForAnalysis(BOOL newRetrieveDataForAnalysis)
    {
        bRetrieveDataForAnalysis = newRetrieveDataForAnalysis;
    }
    const char *GetMatchTypeStr(int Type);
    void SetLoadDiffResults(bool NewLoadDiffResults)
    {
        LoadDiffResults = NewLoadDiffResults;
    }
    void SetLoadIDAController(bool NewLoadIDAController)
    {
        LoadIDAController = NewLoadIDAController;
    }

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
    BREAKPOINTS ShowUnidentifiedAndModifiedBlocks();
	void PrintMatchMapInfo();
};

