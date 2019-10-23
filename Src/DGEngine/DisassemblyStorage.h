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

	virtual int ProcessTLV(BYTE Type, PBYTE Data, DWORD Length);

	virtual void AddBasicBlock(PBasicBlock p_basic_block);
	virtual void AddMapInfo(PMapInfo p_map_info);

	virtual void ReadFunctionAddressMap(int fileID, unordered_set <va_t> &functionAddressMap);
	virtual char* ReadFingerPrint(int fileID, va_t address);
	virtual char* ReadName(int fileID, va_t address);
	virtual va_t ReadBlockStartAddress(int fileID, va_t address);
	virtual void ReadBasicBlockInfo(int fileID, char* conditionStr, AnalysisInfo* analysisInfo);
	virtual multimap <va_t, PMapInfo>* ReadMapInfo(int fileID, va_t address = 0, bool isFunction = false);
	virtual vector<MatchData*>* ReadMatchMap(int sourceID, int targetID, int index, va_t address, bool erase);
	virtual MatchResults *ReadMatchResults(int sourceID, int targetID);

	virtual list<BLOCK> ReadFunctionMemberAddresses(int fileID, va_t function_address);

	virtual vector <FunctionMatchInfo> QueryFunctionMatches(char* query, int sourceID, int targetID);

	virtual void InsertMatchMap(int sourceFileID, int targetFileID, va_t sourceAddress, va_t targetAddress, int matchType, int matchRate);
	virtual char* GetOriginalFilePath(int fileID);
	virtual void DeleteMatchInfo(int fileID, va_t functionAddress);

	virtual char* ReadDisasmLine(int fileID, va_t startAddress);
	virtual PBasicBlock ReadBasicBlock(int fileID, va_t address);
	virtual void UpdateBasicBlock(int fileID, va_t address1, va_t address2);
};
