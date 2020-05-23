#pragma once
#include <unordered_set>
#include <unordered_map>

#include "windows.h"
#include <vector>

#include "windows.h"
#include "StorageDataStructures.h"

using namespace std;
using namespace stdext;

#pragma pack(push)
#pragma pack(1)

typedef int va_t;

#ifdef _DEBUGX
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

#define LOG_DARUNGRIM			0x00000001
#define LOG_DIFF_MACHINE		0x00000002
#define LOG_IDA_CONTROLLER		0x00000004
#define LOG_SQL					0x00000008
#define LOG_BASIC_BLOCK	0x0000000F
#define LOG_MATCH_RATE			0x00000010

#define DREF 0
#define CREF 1
#define FUNCTION 2
#define STACK 3
#define NAME 4
#define DISASM_LINE 5
#define DATA_TYPE 6

struct FileList
{
	string SourceFilename;
	string TargetFilename;
};

typedef struct _FingerPrintInfo_ {
	va_t addr;
} FingerPrintInfo,  *PFingerPrintInfo;

typedef struct _FunctionMatchInfo_
{
	va_t SourceAddress;
	va_t EndAddress;
	va_t TargetAddress;
	short BlockType;
	short MatchRate;
	char *SourceFunctionName;
	short Type;
	char *TargetFunctionName;
	int MatchCountForTheSource;
	int NoneMatchCountForTheSource;
	int MatchCountWithModificationForTheSource;
	int MatchCountForTheTarget;
	int NoneMatchCountForTheTarget;
	int MatchCountWithModificationForTheTarget;
} FunctionMatchInfo;

class FunctionMatchInfoList
{
private:
    vector <FunctionMatchInfo> m_functionMatchInfoList;

public:
	template<typename T>
	struct Iterator {
		T* p;
		T& operator*() { return *p; }
		bool operator != (const Iterator& rhs) {
			return p != rhs.p;
		}
		void operator ++() { ++p; }
	};
	
	auto begin() const
    {
		return m_functionMatchInfoList.begin();
	}

	auto end() const
    {
		return m_functionMatchInfoList.end();
	}

    void Add(FunctionMatchInfo functionMatchInfo)
    {
        m_functionMatchInfoList.push_back(functionMatchInfo);
    }

	int Size()
	{
		return m_functionMatchInfoList.size();
	}

    void ClearFunctionMatchList()
    {
        for (auto& val : m_functionMatchInfoList)
        {
            free(val.SourceFunctionName);
            free(val.TargetFunctionName);
        }
        m_functionMatchInfoList.clear();
    }    
};

class hash_compare_fingerprint
{
public:
	enum
	{
		bucket_size = 400000,
		min_buckets = 4000
	};
public:
	size_t operator() (/*[in]*/ const unsigned char *Bytes) const
	{
		size_t Key = 0;
		for (int i = 0; i < *(unsigned short*)Bytes; i++)
		{
			Key += Bytes[sizeof(short) + i];
		}
		return  Key;
	}
public:
	bool operator() (/*[in]*/const unsigned char *Bytes01,/*[in]*/ const unsigned char *Bytes02) const
	{
		if (Bytes01 == Bytes02)
		{
			return 0;
		}

		if (*(unsigned short*)Bytes01 == *(unsigned short*)Bytes02)
		{
			return (memcmp(Bytes01 + sizeof(unsigned short), Bytes02 + sizeof(unsigned short), *(unsigned short*)Bytes01) < 0);
		}
		return (*(unsigned short*)Bytes01 >  *(unsigned short*)Bytes02);
	}
};

//,hash_compare<string,equ_str> 
typedef struct _AnalysisInfo_ {
	FileInfo file_info;
	multimap <va_t, PBasicBlock> address_map;
	multimap <va_t, string> address_disassembly_map;
	multimap <unsigned char*, va_t, hash_compare_fingerprint> fingerprint_map;
	multimap <va_t, unsigned char*> address_fingerprint_map;
	multimap <string, va_t> name_map;
	multimap <va_t, string> address_name_map;
	multimap <va_t, PMapInfo> map_info_map;
} AnalysisInfo,  *PAnalysisInfo;

typedef struct _MatchData_ {
	short Type;
	short SubType;
	short Status;
	va_t Addresses[2];
	short MatchRate;
	va_t UnpatchedParentAddress;
	va_t PatchedParentAddress;
} MatchData;

class MatchMapList
{
private:
    vector<MatchData*> m_matchDataList;

public:
	template<typename T>
	struct Iterator {
		T* p;
		T& operator*() { return *p; }
		bool operator != (const Iterator& rhs) {
			return p != rhs.p;
		}
		void operator ++() { ++p; }
	};
	
	auto begin() const { // const version
		return m_matchDataList.begin();
	}
	auto end() const { // const version
		return m_matchDataList.end();
	}

	int Size()
	{
		return m_matchDataList.size();
	}

    void Add(MatchData *new_match_data)
    {
        m_matchDataList.push_back(new_match_data);
    }
  
    void FreeMatchMapList()
    {
        for (vector<MatchData*>::iterator it = m_matchDataList.begin(); it != m_matchDataList.end(); it++)
        {
            if (*it)
            {
                delete (*it);
            }
        }
    }

    va_t GetAddress(int index)
    {
        for (vector<MatchData*>::iterator it = m_matchDataList.begin(); it != m_matchDataList.end(); it++)
        {            
            return (*it)->Addresses[index];
        }
    }

    int GetMaxMatchRate()
    {
        int maxMatchRate = 0;
        if (m_matchDataList.size() > 0)
        {
            for (vector<MatchData*>::iterator it = m_matchDataList.begin(); it != m_matchDataList.end(); it++)
            {
                if ((*it)->MatchRate > maxMatchRate)
                {
                    maxMatchRate = (*it)->MatchRate;
                }
            }
        }
        
        return maxMatchRate;
    }

    void Print()
    {
        if (m_matchDataList.size() > 0)
        {
            for (vector<MatchData*>::iterator it = m_matchDataList.begin(); it != m_matchDataList.end(); it++)
            {
                //TODO: Logger.Log(10, LOG_DIFF_MACHINE, "Basic Block: %X Match Rate: %d%%\n", (*blockIterator).Start, (*it)->MatchRate);
            }
        }
        else
        {
            //TODO: Logger.Log(10, LOG_DIFF_MACHINE, "Basic Block: %X Has No Match.\n", (*blockIterator).Start);
        }
    }
};

enum { NAME_MATCH, FINGERPRINT_MATCH, TWO_LEVEL_FINGERPRINT_MATCH, TREE_MATCH, FINGERPRINT_INSIDE_FUNCTION_MATCH, FUNCTION_MATCH };

typedef struct _AnalysisInfoList_ {
	PAnalysisInfo p_analysis_info;
	SOCKET socket;
	va_t address;
	struct _AnalysisInfoList_ *prev;
	struct _AnalysisInfoList_ *next;
} AnalysisInfoList;

typedef pair <va_t, PBasicBlock> AddrPBasicBlock_Pair;
typedef pair <va_t, string> AddrDisassembly_Pair;
typedef pair <unsigned char*, va_t> FingerPrintAddress_Pair;
typedef pair <string, va_t*> TwoLevelFingerPrintAddress_Pair;
typedef pair <va_t, unsigned char*> AddressFingerPrintAddress_Pair;
typedef pair <string, va_t> NameAddress_Pair;
typedef pair <va_t, string> AddressName_Pair;
typedef pair <va_t, MatchData> MatchMap_Pair;
typedef pair <unsigned char*, unsigned char*> Fingerprint_Pair;

#define STATUS_TREE_CHECKED 0x00000001
#define STATUS_MAPPING_DISABLED 0x2

class BREAKPOINTS
{
public:
	unordered_set<va_t> SourceFunctionMap;
	unordered_set<va_t> SourceAddressMap;

	unordered_set<va_t> TargetFunctionMap;
	unordered_set<va_t> TargetAddressMap;
};


#pragma pack(pop)
