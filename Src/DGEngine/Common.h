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
#define LOG_BINARIES		0x00000004
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

typedef struct _InstructionHashInfo_ {
	va_t addr;
} InstructionHashInfo,  *PInstructionHashInfo;

typedef struct _FunctionMatchInfo_
{
	va_t SourceAddress;
	va_t EndAddress;
	va_t TargetAddress;
	short BlockType;
	short MatchRate;
	string SourceFunctionName;
	short Type;
	string TargetFunctionName;
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
        m_functionMatchInfoList.clear();
    }    
};
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

typedef struct _DisassemblyHashMapsList_ {
	PDisassemblyHashMaps p_analysis_info;
	SOCKET socket;
	va_t address;
	struct _DisassemblyHashMapsList_ *prev;
	struct _DisassemblyHashMapsList_ *next;
} DisassemblyHashMapsList;

typedef pair <va_t, string> AddrDisassembly_Pair;
typedef pair <unsigned char*, va_t> InstructionHashAddress_Pair;
typedef pair <string, va_t*> TwoLevelInstructionHashAddress_Pair;
typedef pair <string, va_t> NameAddress_Pair;
typedef pair <va_t, string> AddressName_Pair;
typedef pair <va_t, MatchData> MatchMap_Pair;
typedef pair <unsigned char*, unsigned char*> InstructionHash_Pair;

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
