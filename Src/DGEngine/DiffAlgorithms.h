#pragma once

#include "MatchResults.h"
#include "Binary.h"

#define DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING 1

typedef struct _AddressesInfo_
{
	int Overflowed;
	va_t SourceAddress;
	va_t TargetAddress;
} AddressesInfo;

class DiffAlgorithms
{
private:
	int DebugFlag;
	DumpAddressChecker *m_pdumpAddressChecker;
	Binary *m_psourceBinary;
	Binary *m_ptargetBinary;    
	void RevokeTreeMatchMapIterInfo(MATCHMAP *pMatchMap, va_t address, va_t match_address);

public:
	DiffAlgorithms();
	~DiffAlgorithms();
	void PurgeInstructionHashHashMap(MATCHMAP *pTemporaryMap);
	void DumpMatchMapIterInfo(const char *prefix, multimap <va_t, MatchData>::iterator match_map_iter);
	const char* GetMatchTypeStr(int Type);
	void RemoveDuplicates(MATCHMAP* pMatchMap);    
};
