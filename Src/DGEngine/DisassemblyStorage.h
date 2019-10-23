#pragma once
#include<iostream>
#include <unordered_set>

using namespace std;
using namespace stdext;

#include "IDAAnalysisCommon.h"
#include "DataStructure.h"
#include "MatchResults.h"
using namespace std;

class DisassemblyStorage
{
public:
	virtual void SetFileInfo(FileInfo* p_file_info);

	virtual int BeginTransaction();
	virtual int EndTransaction();
	virtual void EndAnalysis();

	virtual void AddBasicBlock(PBasicBlock p_basic_block);
	virtual void AddMapInfo(PMapInfo p_map_info);

	virtual void ReadFunctionAddressMap(int fileID, unordered_set <va_t> &functionAddressMap);
	char* ReadFingerPrint(int fileID, va_t address);
	char* ReadName(int fileID, va_t address);
	va_t ReadBlockStartAddress(int fileID, va_t address);
	void ReadBasicBlockInfo(int fileID, char* conditionStr, AnalysisInfo* analysisInfo);
	multimap <va_t, PMapInfo>* ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false);
	vector<MatchData*>* ReadMatchMap(int sourceID, int targetID, int index, va_t address, bool erase);
	MatchResults *ReadMatchResults(int sourceID, int targetID);
	vector <FunctionMatchInfo> QueryFunctionMatches(char* query, int sourceID, int targetID);

	void InsertMatchMap(int sourceFileID, int targetFileID, va_t sourceAddress, va_t targetAddress, int matchType, int matchRate);
};
