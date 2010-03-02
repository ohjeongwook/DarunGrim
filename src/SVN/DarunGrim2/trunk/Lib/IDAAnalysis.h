#pragma warning (disable: 4819)
#pragma warning (disable: 4996)
#pragma warning (disable : 4786)

#pragma once
#include <windows.h>
#include "IdaIncludes.h"
#include <map>
#include <hash_map>
#include <hash_set>
#include <queue>
#include <list>

using namespace std;
using namespace stdext;

/****************************************************************************************************************/
/* Location Info && AddrMapHash structures and routines*/

typedef struct _LocationInfo_{
	ea_t address;
#define UNKNOWN 0
#define CODE 1
#define FUNCTION 2
#define DATA 3
	int BlockType;
	flags_t Flag;
#ifdef SAVE_NAME
	char name[1024];
	char function_name[1024];
#else
	char name[1];
	char function_name[1];
#endif
	size_t block_size;
	int instruction_count;
	DWORD block_reference_count;
	func_t *p_func_t;

	int prev_drefs_size;
	ea_t *prev_drefs;

	int prev_crefs_size;
	ea_t *prev_crefs;

	int next_crefs_size;
	ea_t *next_crefs;

	int call_addrs_size;
	ea_t *call_addrs;

	int next_drefs_size;
	ea_t *next_drefs;

	ea_t checked_function_consistency;
	int FunctionAddressSize;
	ea_t *FunctionAddresses;

	bool saved;
	struct _LocationInfo_ *linked_node; 
	struct _LocationInfo_ *next; 
} LocationInfo;

typedef struct _AddrMapHash_{
	ea_t address;
	LocationInfo *p_location_info;
	struct _AddrMapHash_ *branch;
} AddrMapHash;


bool StartProcess(LPTSTR szCmdline);

//Key=op_t Operand
typedef struct
{
	ea_t Address;
	int Index;
} OperandPosition;

class OperandPositionCompareTrait
{
public:
	static const size_t bucket_size = 100;
	static const size_t min_buckets = 8;

	size_t operator()(const OperandPosition& x) const
	{
		size_t key=0;
		key=x.Address*10+x.Index;
		return key;
	}

	bool operator()(const OperandPosition & x, const OperandPosition & y) const 
	{
		return (y.Address*10+y.Index)<(x.Address*10+x.Index);
		//return memcmp(&x,&y,sizeof(x));
	}
};

struct OpTHashCompareStr
{
	static const size_t bucket_size = 100;
	static const size_t min_buckets = 8;

	size_t operator()(const op_t& x) const
	{
		size_t key=0;
		key=x.type;
		if(x.type==o_reg)
		{
			key+=x.reg*100;
		}else if(x.type==o_displ)
		{
			key+=x.reg*100;
			key+=x.phrase*10000;
		}else if(x.type==o_phrase)
		{
			key+=x.phrase*100;
			key+=x.specflag1*10000;
		}
		return key;
	}

	bool operator()(const op_t & x, const op_t & y) const 
	{
		if(x.type!=y.type)
		{
			return x.type<y.type;
		}else
		{
			if(x.type==o_reg)
			{
				return x.reg<y.reg;
			}else if(x.type==o_displ)
			{
				if(x.reg!=y.reg)
				{
					return x.reg<y.reg;
				}else
				{
					return x.phrase<y.phrase;
				}
			}else if(x.type==o_phrase)
			{
				if(x.phrase!=y.phrase)
				{
					return x.phrase<y.phrase;
				}else
				{
					return x.specflag1<y.specflag1;
				}
			}
			return 0;
		}
	}
};

extern char *OpTypeStr[];

string GetFeatureStr(ulong features);
void GetFeatureBits(int itype,char *FeatureMap,int Size);
void DumpOperand(HANDLE hFile,op_t operand);
void AddInstructionByOrder(hash_map <ea_t,insn_t> &InstructionHash,list <ea_t> &Addresses,ea_t Address);
list <insn_t> *ReoderInstructions(multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> &InstructionMap,hash_map <ea_t,insn_t> &InstructionHash);
list <int> GetRelatedFlags(int itype,bool IsModifying);
void UpdateInstructionMap
(
	hash_map <op_t,OperandPosition,OpTHashCompareStr> &OperandsHash,
	hash_map <int,ea_t> &FlagsHash,
	//Instruction Hash and Map
	multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> &InstructionMap,
	hash_map <ea_t,insn_t> &InstructionHash,
	insn_t &instruction
);
void DumpDOT(
	char *Filename,
	multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> &InstructionMap,
	hash_map <ea_t,insn_t> &InstructionHash
);

AddrMapHash *AddToAddrMap(AddrMapHash *addr_map_hash,LocationInfo *p_location_info);
LocationInfo *FindFromAddrMap(AddrMapHash *addr_map_hash,ea_t address);
void DumpAddressInfo(ea_t address);
void DumpLocationInfo(AddrMapHash *addr_map_base,ea_t address);
bool MakeMemberOfFunction(AddrMapHash *addr_map_base,ea_t function_start_address,LocationInfo *p_location_info);
void CheckLocationInfos(AddrMapHash *addr_map_base,LocationInfo *p_first_location_info);
bool AnalyzeRegion(AddrMapHash **p_addr_map_base,LocationInfo **p_p_first_location_info);
void AnalyzeIDAData(bool (*Callback)(PVOID context,BYTE type,PBYTE data,DWORD length),PVOID Context,ea_t StartEA,ea_t EndEA,int GatherCmdArray=FALSE);
