#pragma once

#include "MatchResults.h"
#include "IDASession.h"

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
	DumpAddressChecker *pDumpAddressChecker;

	IDASession *SourceIDASession;
	IDASession *TargetIDASession;    


	void RevokeTreeMatchMapIterInfo(MATCHMAP *pMatchMap, va_t address, va_t match_address);

public:
	DiffAlgorithms();
	~DiffAlgorithms();

	void RemoveDuplicates(MATCHMAP* pMatchMap);
	vector <FunctionMatchInfo>* GenerateFunctionMatchInfo(MATCHMAP* pMatchMap, multimap <va_t, va_t>* pReverseAddressMap);
	int GetFingerPrintMatchRate(unsigned char *unpatched_finger_print, unsigned char *patched_finger_print);
    int GetMatchRate(va_t unpatched_address, va_t patched_address);

	MATCHMAP *DoFingerPrintMatchInsideFunction(va_t SourceFunctionAddress, list <va_t>& SourceBlockAddresses, va_t TargetFunctionAddress, list <va_t>& TargetBlockAddresses);
	MATCHMAP *DoFingerPrintMatch();

	void PurgeFingerprintHashMap(MATCHMAP *pTemporaryMap);
    MATCHMAP *DoIsomorphMatch(MATCHMAP *pMainMatchMap, MATCHMAP *pOrigTemporaryMap, MATCHMAP *pTemporaryMap);
    MATCHMAP *DoFunctionMatch(MATCHMAP *pCurrentMatchMap, multimap <va_t, va_t> *functionMembersMapForSource, multimap <va_t, va_t> *functionMembersMapForTarget);

	MatchRateInfo *GetMatchRateInfoArray(va_t source_address, va_t target_address, int type, int& MatchRateInfoCount);
	void DumpMatchMapIterInfo(const char *prefix, multimap <va_t, MatchData>::iterator match_map_iter);
};

