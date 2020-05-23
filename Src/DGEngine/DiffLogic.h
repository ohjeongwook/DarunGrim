#pragma once
#include <vector>
#include <unordered_set>
#include <list>

#include "Common.h"
#include "Loader.h"
#include "LogOperation.h"
#include "MatchResults.h"
#include "DiffAlgorithms.h"

#include "DiffStorage.h"
#include "DisassemblyStorage.h"

class DiffLogic
{
private:
    int DebugFlag;

    bool ShowFullMatched;
    bool ShowNonMatched;

    bool LoadMatchResults;
    bool LoadIDAController;

    int SourceID;
    string SourceDBName;
    va_t SourceFunctionAddress;

    int TargetID;
    string TargetDBName;
    va_t TargetFunctionAddress;

    DiffStorage* m_pdiffStorage;
    DisassemblyStorage* m_psourceStorage;
    DisassemblyStorage* m_ptargetStorage;

    Loader* SourceLoader;
    Loader* TargetLoader;

    MatchResults* m_pMatchResults;
    FunctionMatchInfoList* m_pFunctionMatchInfoList;

    DiffAlgorithms* m_pdiffAlgorithms;

    unordered_set <va_t> m_sourceUnidentifedBlockHash;
    unordered_set <va_t> m_targetUnidentifedBlockHash;

    DumpAddressChecker* m_pdumpAddressChecker;

	BOOL _Load();

public:
    DiffLogic(Loader *the_source = NULL, Loader *the_target = NULL);
    ~DiffLogic();

    void SetDumpAddressChecker(DumpAddressChecker *p_dump_address_checker)
    {
        m_pdumpAddressChecker = p_dump_address_checker;
    }

    void SetSource(Loader *NewSource)
    {
        SourceLoader = NewSource;
    }

    void SetTarget(Loader *NewTarget)
    {
        TargetLoader = NewTarget;
    }

    void SetLoadMatchResults(bool NewLoadMatchResults)
    {
        LoadMatchResults = NewLoadMatchResults;
    }
    void SetLoadIDAController(bool NewLoadIDAController)
    {
        LoadIDAController = NewLoadIDAController;
    }

    void SetSource(const char* db_filename, DWORD id = 1, va_t function_address = 0)
    {
        SourceDBName = db_filename;
        SourceID = id;
        SourceFunctionAddress = function_address;
    }

    void SetTarget(const char* db_filename, DWORD id = 1, va_t function_address = 0)
    {
        TargetDBName = db_filename;
        TargetID = id;
        TargetFunctionAddress = function_address;
    }

    void SetSource(DisassemblyStorage* disassemblyStorage, DWORD id = 1, va_t function_address = 0)
    {
        m_psourceStorage = disassemblyStorage;
        SourceID = id;
        SourceFunctionAddress = function_address;
    }

    void SetTarget(DisassemblyStorage* disassemblyStorage, DWORD id = 1, va_t function_address = 0)
    {
        m_ptargetStorage = disassemblyStorage;
        TargetID = id;
        TargetFunctionAddress = function_address;
    }

    void SetTargetFunctions(va_t ParamSourceFunctionAddress, va_t ParamTargetFunctionAddress)
    {
        SourceFunctionAddress = ParamSourceFunctionAddress;
        TargetFunctionAddress = ParamTargetFunctionAddress;
    }

    BOOL Create(const char* DiffDBFilename);
    BOOL Load(const char* DiffDBFilename);
    BOOL Load(DiffStorage *p_diffStorage, DisassemblyStorage  *p_disassemblyStorage);

    Loader *GetSourceLoader();
    Loader *GetTargetLoader();

    void AppendToMatchMap(MATCHMAP* pBaseMap, MATCHMAP* pTemporaryMap);
    MatchMapList* GetMatchData(int index, va_t address, BOOL erase = FALSE);
    va_t GetMatchAddr(int index, va_t address);
    int GetMatchRate(va_t unpatched_address, va_t patched_address);
    void RemoveMatchData(va_t source_address, va_t target_address);
    void PrintMatchMapInfo();

    va_t DumpFunctionMatchInfo(int index, va_t address);

    void GetMatchStatistics(va_t address, int index, int& found_match_number, int& found_match_with_difference_number, int& not_found_match_number, float& matchrate);

    void ShowDiffMap(va_t unpatched_address, va_t patched_address);
    void TestFunctionMatchRate(int index, va_t Address);
    void RetrieveNonMatchingMembers(int index, va_t FunctionAddress, list <va_t>& Members);
    bool TestAnalysis();
    MATCHMAP* DoFunctionLevelMatchOptimizing(FunctionMatchInfoList* pFunctionMatchInfoList);
    bool Analyze();
    void AnalyzeFunctionSanity();

    int GetUnidentifiedBlockCount(int index);
    CodeBlock GetUnidentifiedBlock(int index, int i);
    BOOL IsInUnidentifiedBlockHash(int index, va_t address);
    BOOL Save(DisassemblyStorage& disassemblyStorage, unordered_set <va_t> *pTheSourceSelectedAddresses = NULL, unordered_set <va_t> *pTheTargetSelectedAddresses = NULL);
    BREAKPOINTS ShowUnidentifiedAndModifiedBlocks();
};
