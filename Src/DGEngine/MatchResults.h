#pragma once
#include <vector>
#include <unordered_set>
#include <list>

#include "Common.h"

const enum { DiffMachineFileSQLiteFormat };

enum { TYPE_MATCH, TYPE_REVERSE_MATCH, TYPE_BEFORE_UNIDENTIFIED_BLOCK, TYPE_AFTER_UNIDENTIFIED_BLOCK };

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

class MatchResults
{
public:
    MATCHMAP MatchMap;
    multimap <va_t, va_t> ReverseAddressMap;
    DumpAddressChecker *pDumpAddressChecker;

public:
    MatchResults();
    void SetDumpAddressChecker(DumpAddressChecker *p_dump_address_checker);
    void Clear();
    void EraseSource(vector <va_t>& addresses, va_t address, va_t source, va_t target);
    void EraseTarget(vector <va_t>& addresses, va_t address, va_t source, va_t target);
    void Erase(va_t source, va_t target);
    multimap <va_t, MatchData>::iterator Erase(multimap <va_t, MatchData>::iterator match_map_iter);
    void AddMatchData(MatchData& match_data, const char *debug_str);
    void Append(MATCHMAP *pTemporaryMap);
    void CleanUp();
};


typedef struct
{
	va_t Source;
	va_t Target;
	int MatchRate;
	int IndexDiff;
} MatchRateInfo;