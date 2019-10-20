#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include "IDAAnalysisCommon.h"
#include "IDAAnalysis.h"

#include "DisassemblyStorage.h"
#include <vector>
#include <unordered_set>
#include <list>
#include <string>

using namespace std;
using namespace stdext;
int Debug=1;
#include "dprintf.h"

HANDLE gLogFile=INVALID_HANDLE_VALUE;

string GetFeatureStr(DWORD features)
{
	string FeatureStr=" ";
	if(features&CF_STOP)
		FeatureStr+="CF_STOP ";
	if(features&CF_CALL)
		FeatureStr+="CF_CALL ";
	if(features&CF_CHG1)
		FeatureStr+="CF_CHG1 ";
	if(features&CF_CHG2)
		FeatureStr+="CF_CHG2 ";
	if(features&CF_CHG3)
		FeatureStr+="CF_CHG3 ";
	if(features&CF_CHG4)
		FeatureStr+="CF_CHG4 ";
	if(features&CF_CHG5)
		FeatureStr+="CF_CHG5 ";
	if(features&CF_CHG6)
		FeatureStr+="CF_CHG6 ";
	if(features&CF_USE1)
		FeatureStr+="CF_USE1 ";
	if(features&CF_USE2)
		FeatureStr+="CF_USE2 ";
	if(features&CF_USE3)
		FeatureStr+="CF_USE3 ";
	if(features&CF_USE4)
		FeatureStr+="CF_USE4 ";
	if(features&CF_USE5)
		FeatureStr+="CF_USE5 ";
	if(features&CF_USE6)
		FeatureStr+="CF_USE6 ";
	if(features&CF_JUMP)
		FeatureStr+="CF_JUMP ";
	if(features&CF_SHFT)
		FeatureStr+="CF_SHFT ";
	if(features&CF_HLL)
		FeatureStr+="CF_HLL ";
	return FeatureStr;
}

#define CF_USE 1
#define CF_CHG 2

void GetFeatureBits(int itype, char *FeatureMap, int Size, insn_t insn)
{
	memset(FeatureMap,0,Size);
	if(Size<sizeof(char)*6)
		return;
	DWORD features=ph.instruc[itype].feature;	
	if(features&CF_CHG1)
		FeatureMap[0]|=CF_CHG;
	if(features&CF_CHG2)
		FeatureMap[1]|=CF_CHG;
	if(features&CF_CHG3)
		FeatureMap[2]|=CF_CHG;
	if(features&CF_CHG4)
		FeatureMap[3]|=CF_CHG;
	if(features&CF_CHG5)
		FeatureMap[4]|=CF_CHG;
	if(features&CF_CHG6)
		FeatureMap[5]|=CF_CHG;

	if(features&CF_USE1)
		FeatureMap[0]|=CF_USE;
	if(features&CF_USE2)
		FeatureMap[1]|=CF_USE;
	if(features&CF_USE3)
		FeatureMap[2]|=CF_USE;
	if(features&CF_USE4)
		FeatureMap[3]|=CF_USE;
	if(features&CF_USE5)
		FeatureMap[4]|=CF_USE;
	if(features&CF_USE6)
		FeatureMap[5]|=CF_USE;

	if(ph.id == PLFM_ARM && 
		(
            insn.itype == ARM_stm && //STMFD SP!,...
            insn.ops[0].type == o_reg &&
            insn.ops[0].reg == 0xd //SP
		)
	)
	{
		FeatureMap[0]|=CF_CHG;
	}
}

char *OpTypeStr[]={
	"o_void",
	"o_reg",
	"o_mem",
	"o_phrase",
	"o_displ",
	"o_imm",
	"o_far",
	"o_near",
	"o_idpspec0",
	"o_idpspec1",
	"o_idpspec2",
	"o_idpspec3",
	"o_idpspec4",
	"o_idpspec5",
	"o_last"};

void DumpOperand(HANDLE hFile,op_t operand)
{
    /* TODO: Conert ph.regNames to ph.get_reg_name
	if(operand.type == o_reg)
	{
        qstring name;
        ph.get_reg_name(&name, operand.reg, operand.dtype, 0);

		WriteToLogFile(hFile,"%s %s(%u)",
			OpTypeStr[operand.type],
            name.c_str(),         
			operand.reg);
	}else if(operand.type == o_displ)
	{
		WriteToLogFile(hFile,"%s %s+%X",
			OpTypeStr[operand.type],
			ph.regNames[operand.reg],
			operand.phrase);
	}else if(operand.type == o_imm)
	{
		WriteToLogFile(hFile,"%s %X",
			OpTypeStr[operand.type],
			operand.value);
	}else if(operand.type == o_near)
	{
		WriteToLogFile(hFile,"%s %X",
			OpTypeStr[operand.type],
			operand.addr);
	}else if(operand.type == o_mem)
	{
		WriteToLogFile(hFile,"%s %X",
			OpTypeStr[operand.type],
			operand.addr);
	}else if(operand.type == o_phrase)
	{
		WriteToLogFile(hFile,"%s %s+%s",
			OpTypeStr[operand.type],
			ph.regNames[operand.phrase],
			ph.regNames[operand.specflag1]);
	}else
	{
		WriteToLogFile(hFile,"%s dtyp=0x%X addr=0x%X value=0x%X specval=0x%X reg=%s phrase=0x%X",
			OpTypeStr[operand.type],
			operand.dtyp,
			operand.addr,
			operand.value,
			operand.specval,
			ph.regNames[operand.reg],
			operand.phrase);
	}
    */

	/*
	if(operand.hasSIB)
	{
		WriteToLogFile(hFile," sib_base=%s sib_index=%s",
			ph.regNames[sib_base(operand)],
			ph.regNames[sib_index(operand)]);
	}*/
}

int GetInstructionWeight(insn_t instruction)
{
	int Weight=0;
	Weight=instruction.itype*1000;
	for(int i=0;i<UA_MAXOP;i++)
	{
		if(instruction.ops[i].type>0)
		{
			Weight+=instruction.ops[i].type*100;
			if(instruction.ops[i].type == o_reg)
			{
				Weight+=instruction.ops[i].reg;
			}
            else if(instruction.ops[i].type == o_displ)
			{
				Weight+=instruction.ops[i].reg;
				Weight+=instruction.ops[i].phrase;
			}
            else if(instruction.ops[i].type == o_imm)
			{
				//Weight+=instruction.ops[i].value;
			}
            else if(instruction.ops[i].type == o_near)
			{
				//Weight+=instruction.ops[i].addr;
			}
            else if(instruction.ops[i].type == o_mem)
			{
				//Weight+=instruction.ops[i].addr;
			}
            else if(instruction.ops[i].type == o_phrase)
			{
				Weight+=instruction.ops[i].phrase+instruction.ops[i].specflag1;
			}
            else
			{
				/*
					instruction.ops[i].dtyp,
					instruction.ops[i].addr,
					instruction.ops[i].value,
					instruction.ops[i].specval,
					ph.regNames[instruction.ops[i].reg],
					instruction.ops[i].phrase*/
			}
		}
	}
	return Weight;
}

char *EscapeString(qstring &input_string)
{
	//<>{}|
	char *buffer=(char *)malloc(input_string.length() *2+1);
	int j=0;
	for(int i=0;i< input_string.length() +1;i++,j++)
	{
        char ch = input_string[i];
		if(ch == '<' || ch == '>' || ch == '{' || ch == '}' || ch == '|')
		{
            buffer[j] = '\\';
			j++;
            buffer[j] = ch;
		}else
		{
            buffer[j] = ch;
		}
	}
	return buffer;
}

void AddInstructionByOrder(unordered_map <ea_t,insn_t> &InstructionHash,list <ea_t> &Addresses,ea_t Address)
{
	unordered_map <ea_t,insn_t>::iterator InstructionHashIter=InstructionHash.find(Address);

	bool IsInserted=FALSE;
	list <ea_t>::iterator AddressesIter;
	for(AddressesIter=Addresses.begin();AddressesIter!=Addresses.end();AddressesIter++)
	{
		unordered_map <ea_t,insn_t>::iterator CurrentInstructionHashIter=InstructionHash.find(*AddressesIter);
		if(GetInstructionWeight(CurrentInstructionHashIter->second)<GetInstructionWeight(InstructionHashIter->second))
		{
			Addresses.insert(AddressesIter,Address);
			IsInserted=TRUE;
			break;
		}
	}
	if(!IsInserted)
		Addresses.push_back(Address);
}

list <insn_t> *ReoderInstructions(multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> &InstructionMap,unordered_map <ea_t,insn_t> &InstructionHash)
{
	list <insn_t> *CmdArray=new list <insn_t>;
	unordered_set <ea_t> ChildAddresses;
	multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait>::iterator InstructionMapIter;

	for(InstructionMapIter=InstructionMap.begin();InstructionMapIter!=InstructionMap.end();InstructionMapIter++)
	{
		ChildAddresses.insert(InstructionMapIter->second.Address);
	}

	list <ea_t> RootAddresses;
	unordered_map <ea_t,insn_t>::iterator InstructionHashIter;
	for(InstructionHashIter=InstructionHash.begin();InstructionHashIter!=InstructionHash.end();InstructionHashIter++)
	{
		if(ChildAddresses.find(InstructionHashIter->first) == ChildAddresses.end())
		{
			AddInstructionByOrder(InstructionHash,RootAddresses,InstructionHashIter->first);
		}
	}
	WriteToLogFile(gLogFile,"InstructionHash=%u, RootAddresses=%u entries\r\n",InstructionHash.size(),RootAddresses.size());

	list <ea_t> OrderedAddresses;
	list <string> Signatures;
	unordered_set <ea_t>::iterator RootAddressesIter;
	for(RootAddressesIter=RootAddresses.begin();RootAddressesIter!=RootAddresses.end();RootAddressesIter++)
	{
		list <ea_t> TargetAddresses;
		list <ea_t>::iterator TargetAddressesIter;
		TargetAddresses.push_back(*RootAddressesIter);
		list <insn_t> Signature;
		WriteToLogFile(gLogFile,"RootAddressesIter=%X ",*RootAddressesIter);
		for(TargetAddressesIter=TargetAddresses.begin();TargetAddressesIter!=TargetAddresses.end();TargetAddressesIter++)
		{
			for(int Index=0;Index<UA_MAXOP;Index++)
			{
				OperandPosition TargetOperandPosition;
				TargetOperandPosition.Address=*TargetAddressesIter;
				TargetOperandPosition.Index=Index;
				
				list <ea_t> ChildrenAddresses;
				list <ea_t>::iterator ChildrenAddressesIter;

				for(InstructionMapIter=InstructionMap.find(TargetOperandPosition);InstructionMapIter!=InstructionMap.end() && InstructionMapIter->first.Address == *TargetAddressesIter && InstructionMapIter->first.Index == Index;InstructionMapIter++)
				{
					AddInstructionByOrder(InstructionHash,ChildrenAddresses,InstructionMapIter->second.Address);
				}
				for(ChildrenAddressesIter=ChildrenAddresses.begin();ChildrenAddressesIter!=ChildrenAddresses.end();ChildrenAddressesIter++)
				{
					TargetAddresses.push_back(*ChildrenAddressesIter);
				}
			}
		}
		//TargetAddresses has all the addresses traversed using BFS
		//Convert it to string and add to string list.
		for(TargetAddressesIter=TargetAddresses.begin();TargetAddressesIter!=TargetAddresses.end();TargetAddressesIter++)
		{
			WriteToLogFile(gLogFile,"%X-",*TargetAddressesIter);
			OrderedAddresses.push_back(*TargetAddressesIter);
		}
		//Signatures.push_back();
		WriteToLogFile(gLogFile,"\r\n");
	}

	//OrderedAddresses
	list <ea_t>::reverse_iterator OrderedAddressesIter;
	for(OrderedAddressesIter=OrderedAddresses.rbegin();OrderedAddressesIter!=OrderedAddresses.rend();OrderedAddressesIter++)
	{
		list <ea_t>::reverse_iterator TmpAddressesIter=OrderedAddressesIter;
		TmpAddressesIter++;
		for(;TmpAddressesIter!=OrderedAddresses.rend();TmpAddressesIter++)
		{
			if(*TmpAddressesIter == *OrderedAddressesIter)
				*TmpAddressesIter=0;
		}
	}

	list <ea_t>::iterator AddressesIter;
	for(AddressesIter=OrderedAddresses.begin();AddressesIter!=OrderedAddresses.end();AddressesIter++)
	{
		InstructionHashIter=InstructionHash.find(*AddressesIter);
		if(InstructionHashIter!=InstructionHash.end())
		{
			WriteToLogFile(gLogFile,"Instruction at %X == %X: ",*AddressesIter,InstructionHashIter->second.ea);
			for(int i=0;i<UA_MAXOP;i++)
			{
				if(InstructionHashIter->second.ops[i].type>0)
				{
					DumpOperand(gLogFile,InstructionHashIter->second.ops[i]);
				}
			}
			WriteToLogFile(gLogFile,"\r\n");

			CmdArray->push_back(InstructionHashIter->second);
		}
	}
	return CmdArray;
}

void DumpDOT(
	char *Filename,
	multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> &InstructionMap,
	unordered_map <ea_t,insn_t> &InstructionHash
)
{
	HANDLE hFile=OpenLogFile(Filename);
	//InstructionMap
	//InstructionHash
	WriteToLogFile(hFile,"digraph g {\r\n\
		graph [\r\n\
		rankdir = \"TB\"\r\n\
		];\r\n\
		node [\r\n\
		fontsize = \"12\"\r\n\
		];\r\n\
		edge [\r\n\
		];\r\n");

	//shape = \"ellipse\"\r\n\

	unordered_map <ea_t,insn_t>::iterator InstructionHashIter;
	//Write Node Data
	for(InstructionHashIter=InstructionHash.begin();InstructionHashIter!=InstructionHash.end();InstructionHashIter++)
	{
		ea_t address=InstructionHashIter->first;
        qstring op_buffer;

        print_insn_mnem(&op_buffer, address);

		WriteToLogFile(hFile,"\"%X\" [\r\n\tlabel=\"%s", address, op_buffer.c_str());
		for(int i=0;i<UA_MAXOP;i++)
		{
			if(InstructionHashIter->second.ops[i].type>0)
			{
				qstring operand_str;

                print_operand(&operand_str, address, i);
				tag_remove(&operand_str,operand_str,0);
				char *escaped_operand_str=EscapeString(operand_str);
				if(escaped_operand_str)
				{
					WriteToLogFile(hFile,"|<f%u>%s",i,escaped_operand_str);
					free(escaped_operand_str);
				}
			}
		}
		WriteToLogFile(hFile,"\"\r\n\tshape=\"record\"\r\n];\r\n\r\n");
	}

	multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait>::iterator InstructionMapIter;
	for(InstructionMapIter=InstructionMap.begin();InstructionMapIter!=InstructionMap.end();InstructionMapIter++)
	{
		WriteToLogFile(hFile,"\"%X\":f%u -> \"%X\":f%u\r\n",
			InstructionMapIter->first.Address,
			InstructionMapIter->first.Index,
			InstructionMapIter->second.Address,
			InstructionMapIter->second.Index);
	}
	CloseLogFile(hFile);
}

enum {CONDITION_FLAG};

list <int> GetRelatedFlags(int itype,bool IsModifying)
{
	list <int> Flags;
	if(IsModifying)
	{
		if(ph.id == PLFM_ARM &&
			(itype == ARM_add ||
			itype == ARM_adc ||
			itype == ARM_sub ||
			itype == ARM_sbc ||
			itype == ARM_rsc ||
			itype == ARM_mul ||
			itype == ARM_mla ||
			itype == ARM_umull ||
			itype == ARM_umlal ||
			itype == ARM_smull ||
			itype == ARM_smlal ||
			itype == ARM_mov ||
			itype == ARM_mvn ||
			itype == ARM_asr ||
			itype == ARM_lsl ||
			itype == ARM_lsr ||
			itype == ARM_ror ||
			//itype == ARM_rrx ||
			itype == ARM_and ||
			itype == ARM_eor ||
			itype == ARM_orr ||
			//itype == ARM_orn ||
			itype == ARM_bic)
		)
		{
			Flags.push_back(CONDITION_FLAG);
		}
	}else
	{
		if(ph.id == PLFM_ARM && itype == ARM_b)
		{
			Flags.push_back(CONDITION_FLAG);
		}
	}
	return Flags;
}

///////////////////////////////////////////////////////////
//Save & Trace Variables
void UpdateInstructionMap
(
	unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn> &OperandsHash,
	unordered_map <int,ea_t> &FlagsHash,
	//Instruction Hash and Map
	multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> &InstructionMap,
	unordered_map <ea_t,insn_t> &InstructionHash,
	insn_t &instruction
)
{
	ea_t address=instruction.ea;
	InstructionHash.insert(pair<ea_t,insn_t>(address,instruction));
	char Features[UA_MAXOP*2];

    insn_t insn;
    decode_insn(&insn, address);

	GetFeatureBits(instruction.itype,Features,sizeof(Features), insn);

	if(Debug>0)
		WriteToLogFile(gLogFile,"%s(%X) %s\r\n",ph.instruc[instruction.itype].name,instruction.itype,GetFeatureStr(ph.instruc[instruction.itype].feature).c_str());

	//Flags Tracing
	list <int> Flags=GetRelatedFlags(instruction.itype,true);
	list <int>::iterator FlagsIter;
	for(FlagsIter=Flags.begin();FlagsIter!=Flags.end();FlagsIter++)
	{
		//Set Flags: FlagsHash
		FlagsHash.insert(pair<int,ea_t>(*FlagsIter,address));
	}

	Flags=GetRelatedFlags(instruction.itype,false);
	for(FlagsIter=Flags.begin();FlagsIter!=Flags.end();FlagsIter++)
	{
		//Use Flags: FlagsHash
		unordered_map <int,ea_t>::iterator FlagsHashIter=FlagsHash.find(*FlagsIter);
		if(FlagsHashIter!=FlagsHash.end())
		{
			//FlagsHashIter->first
			//FlagsHashIter->second
			OperandPosition SrcOperandPosition;
			SrcOperandPosition.Address=FlagsHashIter->second;
			SrcOperandPosition.Index=0;

			OperandPosition DstOperandPosition;
			DstOperandPosition.Address=address;
			DstOperandPosition.Index=0;
			InstructionMap.insert(pair<OperandPosition,OperandPosition>(SrcOperandPosition,DstOperandPosition));
		}
	}
	//Return Value Tracing
	
	
	//Parameter Tracing
	//ARM_blx/ARM_blx1/ARM_blx2
	if(
		(ph.id == PLFM_ARM && (instruction.itype == ARM_bl || instruction.itype == ARM_blx1 || instruction.itype == ARM_blx2)) ||
		(ph.id == PLFM_MIPS && (instruction.itype == MIPS_jal || instruction.itype == MIPS_jalx))
	)
	{
		op_t operand;
		operand.type=o_reg;
		for(int reg=0;reg<5;reg++)
		{
			operand.reg=reg;
			unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn>::iterator iter=OperandsHash.find(operand);
			if(iter!=OperandsHash.end())
			{
				OperandPosition SrcOperandPosition;
				SrcOperandPosition.Address=iter->second.Address;
				SrcOperandPosition.Index=iter->second.Index;

				OperandPosition DstOperandPosition;
				DstOperandPosition.Address=address;
				DstOperandPosition.Index=0;

				InstructionMap.insert(pair<OperandPosition,OperandPosition>(SrcOperandPosition,DstOperandPosition));

			}else
			{
				break;
			}
		}
	}

	//Operand Tracing
	for(int i=UA_MAXOP-1;i>=0;i--)
	{
		op_t *pOperand=&instruction.ops[i];
		if(pOperand->type>0)
		{
			//o_mem,o_displ,o_far,o_near -> addr
			//o_reg -> reg
			//o_phrase,o_displ -> phrase
			//outer displacement (o_displ+OF_OUTER_DISP) -> value
			//o_imm -> value
			WriteToLogFile(gLogFile,"\tOperand %u: [%s%s] ",i,(Features[i]&CF_CHG)?"CHG":"",(Features[i]&CF_USE)?"USE":"");
			if(Features[i]&CF_USE)
			{
				unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn>::iterator iter=OperandsHash.find(*pOperand);
				if(iter == OperandsHash.end())
				{
					op_t tmp_op;
					memset(&tmp_op,0,sizeof(op_t));
					tmp_op.type=o_reg;
					if(pOperand->type == o_displ)
					{
						tmp_op.reg=pOperand->reg;
						iter=OperandsHash.find(tmp_op);
						if(iter == OperandsHash.end())
						{
							tmp_op.reg=pOperand->phrase;
							iter=OperandsHash.find(tmp_op);
						}
					}else if(pOperand->type == o_phrase)
					{
						tmp_op.reg=pOperand->specflag1;
						iter=OperandsHash.find(tmp_op);
						if(iter == OperandsHash.end())
						{
							tmp_op.reg=pOperand->phrase;
							iter=OperandsHash.find(tmp_op);
						}
					}
				}
				if(iter!=OperandsHash.end())
				{
					OperandPosition SrcOperandPosition;
					SrcOperandPosition.Address=iter->second.Address;
					SrcOperandPosition.Index=iter->second.Index;

					OperandPosition DstOperandPosition;
					DstOperandPosition.Address=address;
					DstOperandPosition.Index=i;

					InstructionMap.insert(pair<OperandPosition,OperandPosition>(SrcOperandPosition,DstOperandPosition));
				}
			}

			if(Features[i]&CF_CHG) //Save to hash(addr,i,op_t)
			{
				OperandPosition operand_position;
				operand_position.Address=address;
				operand_position.Index=i;
				OperandsHash.erase(instruction.ops[i]);
				WriteToLogFile(gLogFile,"Inserting %u\r\n",i);
				OperandsHash.insert(pair<op_t,OperandPosition>(instruction.ops[i],operand_position));
			}
		}
	}
}


void IDAAnalyzer::DumpBasicBlock(ea_t src_block_address, list <insn_t> *pCmdArray, flags_t flags, bool GatherCmdArray)
{
	string disasm_buffer;
	
	BasicBlock basic_block;
	basic_block.FunctionAddress=0;
	basic_block.BlockType=UNKNOWN_BLOCK;
	basic_block.StartAddress=src_block_address;
	basic_block.Flag=flags;

	qstring name;

    get_short_name(&name, src_block_address);

	if(is_code(flags))
	{
		func_t *p_func = get_func(src_block_address);
		if(p_func)
		{
			basic_block.FunctionAddress=p_func->start_ea;
		}

		//WriteToLogFile(gLogFile, "Function: %X Block : %X (%s)\n", basic_block.StartAddress, basic_block.FunctionAddress, name);
		//msg("Function: %X Block : %X (%s)\n", basic_block.FunctionAddress, basic_block.StartAddress, name);

		ea_t cref = get_first_cref_to(src_block_address);

		if(cref == BADADDR || basic_block.StartAddress == basic_block.FunctionAddress)
		{
			basic_block.BlockType=FUNCTION_BLOCK;
			if(name[0] == NULL)
			{
				//TODO: Fix - _snprintf(name,sizeof(name)-1,"func_%X",basic_block.StartAddress);
			}
		}
	}

	vector <unsigned char> FingerPrint;

	basic_block.EndAddress=0;

	list <insn_t>::iterator CmdArrayIter;

	for(CmdArrayIter=pCmdArray->begin();
		CmdArrayIter!=pCmdArray->end();
		CmdArrayIter++)
	{
		if(basic_block.EndAddress<(*CmdArrayIter).ea && (*CmdArrayIter).ea!=0xffffffff)
			basic_block.EndAddress=(*CmdArrayIter).ea;
		
		if(is_code(flags) &&
			!( //detect hot patching
				basic_block.StartAddress == basic_block.FunctionAddress && 
				CmdArrayIter == pCmdArray->begin() &&
				(ph.id == PLFM_386 || ph.id == PLFM_IA64) && (*CmdArrayIter).itype == NN_mov && (*CmdArrayIter).ops[0].reg == (*CmdArrayIter).ops[1].reg
			) &&
			!(
				((ph.id == PLFM_386 || ph.id == PLFM_IA64) &&
					(
						(*CmdArrayIter).itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
						(*CmdArrayIter).itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
						(*CmdArrayIter).itype == NN_jc ||                  // Jump if Carry (CF=1)
						(*CmdArrayIter).itype == NN_jcxz ||                // Jump if CX is 0
						(*CmdArrayIter).itype == NN_jecxz ||               // Jump if ECX is 0
						(*CmdArrayIter).itype == NN_jrcxz ||               // Jump if RCX is 0
						(*CmdArrayIter).itype == NN_je ||                  // Jump if Equal (ZF=1)
						(*CmdArrayIter).itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
						(*CmdArrayIter).itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
						(*CmdArrayIter).itype == NN_jo ||                  // Jump if Overflow (OF=1)
						(*CmdArrayIter).itype == NN_jp ||                  // Jump if Parity (PF=1)
						(*CmdArrayIter).itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
						(*CmdArrayIter).itype == NN_js ||                  // Jump if Sign (SF=1)
						(*CmdArrayIter).itype == NN_jz ||                  // Jump if Zero (ZF=1)
						(*CmdArrayIter).itype == NN_jmp ||                 // Jump
						(*CmdArrayIter).itype == NN_jmpfi ||               // Indirect Far Jump
						(*CmdArrayIter).itype == NN_jmpni ||               // Indirect Near Jump
						(*CmdArrayIter).itype == NN_jmpshort ||            // Jump Short
						(*CmdArrayIter).itype == NN_jpo ||                 // Jump if Parity Odd  (PF=0)
						(*CmdArrayIter).itype == NN_jl ||                  // Jump if Less (SF!=OF)
						(*CmdArrayIter).itype == NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
						(*CmdArrayIter).itype == NN_jb ||                  // Jump if Below (CF=1)
						(*CmdArrayIter).itype == NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
						(*CmdArrayIter).itype == NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
						(*CmdArrayIter).itype == NN_jnae ||                // Jump if Not Above or Equal (CF=1)
						(*CmdArrayIter).itype == NN_jnb ||                 // Jump if Not Below (CF=0)
						(*CmdArrayIter).itype == NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
						(*CmdArrayIter).itype == NN_jnc ||                 // Jump if Not Carry (CF=0)
						(*CmdArrayIter).itype == NN_jne ||                 // Jump if Not Equal (ZF=0)
						(*CmdArrayIter).itype == NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
						(*CmdArrayIter).itype == NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
						(*CmdArrayIter).itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
						(*CmdArrayIter).itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
						(*CmdArrayIter).itype == NN_jno ||                 // Jump if Not Overflow (OF=0)
						(*CmdArrayIter).itype == NN_jnp ||                 // Jump if Not Parity (PF=0)
						(*CmdArrayIter).itype == NN_jns ||                 // Jump if Not Sign (SF=0)
						(*CmdArrayIter).itype == NN_jnz                 // Jump if Not Zero (ZF=0)
					)
				) ||
				(
					ph.id == PLFM_ARM &&
					(
						(*CmdArrayIter).itype == ARM_b
					)
				)
			)
		)
		{
			FingerPrint.push_back((unsigned char)(*CmdArrayIter).itype);
			for(int i=0;i<UA_MAXOP;i++)
			{
				if((*CmdArrayIter).ops[i].type!=0)
				{
					FingerPrint.push_back((*CmdArrayIter).ops[i].type);
					FingerPrint.push_back((*CmdArrayIter).ops[i].dtype);
					/*
					if((*CmdArrayIter).ops[i].type == o_imm)
					{
						FingerPrint.push_back(((*CmdArrayIter).ops[i].value>>24)&0xff);
						FingerPrint.push_back(((*CmdArrayIter).ops[i].value>>16)&0xff);
						FingerPrint.push_back(((*CmdArrayIter).ops[i].value>>8)&0xff);								
						FingerPrint.push_back((*CmdArrayIter).ops[i].value&0xff);
					}*/
				}
			}
		}

		if(is_code(flags))
		{
			qstring buf;

			generate_disasm_line(&buf, (*CmdArrayIter).ea);
            tag_remove(&buf);

			if(Debug>3)
				WriteToLogFile(gLogFile,"%X(%X): [%s]\n",(*CmdArrayIter).ea,basic_block.StartAddress,buf);

            buf += "\n";
			disasm_buffer += buf.c_str();
		}
	}

	basic_block.NameLen= name.length() + 1;
	basic_block.DisasmLinesLen=disasm_buffer.length()+1;
	basic_block.FingerprintLen=FingerPrint.size();

	if(GatherCmdArray)
	{
		basic_block.CmdArrayLen=pCmdArray->size()*sizeof(insn_t);
	}else
	{
		basic_block.CmdArrayLen=0;
	}

	int basic_block_length=sizeof(basic_block)+basic_block.NameLen+basic_block.DisasmLinesLen+basic_block.FingerprintLen+basic_block.CmdArrayLen;
	PBasicBlock p_basic_block=(PBasicBlock)malloc(basic_block_length);

	if(p_basic_block)
	{
		memcpy(p_basic_block, &basic_block, sizeof(basic_block));
		memcpy(p_basic_block->Data, name.c_str(), basic_block.NameLen);

		if(disasm_buffer.length()>0)
		{
			memcpy((char *)p_basic_block->Data+basic_block.NameLen,
				disasm_buffer.c_str(),
				basic_block.DisasmLinesLen);
		}else
		{
			*((char *)p_basic_block->Data+basic_block.NameLen)=NULL;
		}

		for(size_t fi=0;fi<FingerPrint.size();fi++)
		{
			((unsigned char *)p_basic_block->Data)[basic_block.NameLen+basic_block.DisasmLinesLen+fi]=FingerPrint.at(fi);
		}

		insn_t *CmdsPtr=(insn_t *)(p_basic_block->Data+basic_block.NameLen+basic_block.DisasmLinesLen+basic_block.FingerprintLen);

		if(GatherCmdArray)
		{
			int CmdArrayIndex=0;
			for(list <insn_t>::iterator iter=pCmdArray->begin();iter!=pCmdArray->end();iter++,CmdArrayIndex++)
			{
				memcpy(&CmdsPtr[CmdArrayIndex],&(*iter),sizeof(insn_t));
			}
		}

        m_disassemblyStorage.AddBasicBlock(p_basic_block);
		free(p_basic_block);
	}
	//Reset FingerPrint Data
	FingerPrint.clear();			
}

ea_t IDAAnalyzer::AnalyzeBlock(ea_t &StartEA,ea_t endEA,list <insn_t> *pCmdArray,flags_t *p_flags,unordered_map <ea_t,ea_t> &AdditionallyAnalyzedBlocks)
{
	while(1)
	{
		unordered_map <ea_t,ea_t>::iterator AdditionallyAnalyzedBlocksIter=AdditionallyAnalyzedBlocks.find(StartEA);
		if(AdditionallyAnalyzedBlocksIter!=AdditionallyAnalyzedBlocks.end())
		{
			//WriteToLogFile(gLogFile,"%s: [AdditionallyAnalyzedBlocksIter] Skip %X block to %X\n",__FUNCTION__,StartEA,AdditionallyAnalyzedBlocksIter->second);
			if(StartEA == AdditionallyAnalyzedBlocksIter->second)
				break;
			StartEA=AdditionallyAnalyzedBlocksIter->second;
		}else
		{
			break;
		}
	}

	ea_t current_addr=StartEA;
	ea_t src_block_address=current_addr;
	ea_t first_block_end_address=0;
	ea_t current_block_start_address=current_addr;

	int InstructionCount=0;
	//WriteToLogFile(gLogFile,"%s: %X~%X\n",__FUNCTION__,current_addr,endEA);

	bool found_branch=FALSE; //first we branch
	for(;current_addr<=endEA;)
	{
		InstructionCount++;
		bool cref_to_next_addr=FALSE;
		*p_flags= get_full_flags(current_addr);
		int current_item_size=get_item_size(current_addr);

		qstring op_buffer;
        print_insn_mnem(&op_buffer, current_addr);

        insn_t insn;
        decode_insn(&insn, current_addr);
		pCmdArray->push_back(insn);
		short current_itype= insn.itype;

		MapInfo map_info;
		//New Location Found
		map_info.SrcBlock=src_block_address;
		//Finding Next CREF
		vector<ea_t> cref_list;
		//cref from
		ea_t cref = get_first_cref_from(current_addr);
		while(cref != BADADDR)
		{
			//if just flowing
			if(cref == current_addr+current_item_size)
			{
				//next instruction...
				cref_to_next_addr=TRUE;
			}else{
				//j* something or call
				//if branching
				//if cmd type is "call"

				if(
					(
                        (ph.id == PLFM_386 || ph.id == PLFM_IA64) && 
                        (insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni)
                    ) ||
					(
                        ph.id == PLFM_ARM && 
                        (insn.itype == ARM_bl || insn.itype == ARM_blx1 || insn.itype == ARM_blx2)
                    ) ||
					(ph.id == PLFM_MIPS && (insn.itype == MIPS_jal || insn.itype == MIPS_jalx))
				)
				{

					//this is a call
					//PUSH THIS: call_addrs cref
					map_info.Type=CALL;
					map_info.Dst=cref;

					m_disassemblyStorage.AddMapInfo(&map_info);
				}else{
					//this is a jump
					found_branch=TRUE; //j* or ret* instruction found
					bool IsNOPBlock=FALSE;
					//check if the jumped position(cref) is a nop block
					//if insn type is "j*"

                    decode_insn(&insn, cref);

					if(insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni || insn.itype == NN_jmpshort)
					{
						int cref_from_cref_number=0;
						ea_t cref_from_cref=get_first_cref_from(cref);
						while(cref_from_cref!=BADADDR)
						{
							cref_from_cref_number++;
							cref_from_cref=get_next_cref_from(cref,cref_from_cref);
						}
						if(cref_from_cref_number == 1)
						{
							//we add the cref's next position instead cref
							//because this is a null block(doing nothing but jump)
							ea_t cref_from_cref=get_first_cref_from(cref);
							while(cref_from_cref!=BADADDR)
							{
								//next_ crefs  cref_from_cref
								cref_list.push_back(cref_from_cref);
								cref_from_cref=get_next_cref_from(cref,cref_from_cref);
							}
							IsNOPBlock=TRUE;
						}
					}
					if(!IsNOPBlock)
					//all other cases
					{
						//PUSH THIS: next_crefs  cref
						cref_list.push_back(cref);
					}
				}
			}
			cref=get_next_cref_from(current_addr,cref);
		}

		if(!found_branch)
		{
			//cref_to
			ea_t cref_to=get_first_cref_to(current_addr+current_item_size);
			while(cref_to!=BADADDR)
			{
				if(cref_to!=current_addr)
				{
					found_branch=TRUE;
					break;
				}
				cref_to=get_next_cref_to(current_addr+current_item_size,cref_to);
			}
			if(!found_branch)
			{
				if(
					((ph.id == PLFM_386 || ph.id == PLFM_IA64) && (insn.itype == NN_retn || insn.itype == NN_retf)) ||
					(ph.id == PLFM_ARM && ((insn.itype == ARM_pop && (insn.ops[0].specval&0xff00) == 0x8000) || insn.itype == ARM_ret || insn.itype == ARM_bx))
				)
				{
					found_branch=TRUE;
				}else if(is_code(*p_flags)!=is_code(get_full_flags(current_addr+current_item_size)))
				{
					//or if code/data type changes
					found_branch=TRUE; //code, data type change...
				}

				if(!found_branch)
				{
					if(!is_code(*p_flags) && has_name(*p_flags))
					{
					    found_branch=TRUE;
					}
				}
			}
		}

		//Skip Null Block
		if(is_code(*p_flags) && 
			found_branch && 
			cref_to_next_addr)
		{
			ea_t cref=current_addr+current_item_size;

            insn_t insn;
            decode_insn(&insn, cref);

			if(insn.itype == NN_jmp || insn.itype == NN_jmpfi || insn.itype == NN_jmpni || insn.itype == NN_jmpshort)
			{
				//we add the cref's next position instead cref
				//because this is a null block(doing nothing but jump)
				ea_t cref_from_cref=get_first_cref_from(cref);
				while(cref_from_cref!=BADADDR)
				{
					//PUSH THIS: next_crefs  cref_from_cref
					cref_list.push_back(cref_from_cref);
					cref_from_cref=get_next_cref_from(cref,cref_from_cref);
				}
			}else
			{
				 //next_crefs  current_addr+current_item_size
				cref_list.push_back(current_addr+current_item_size);
			}
		}

		//dref_to
		ea_t dref=get_first_dref_to(current_addr);
		while(dref!=BADADDR)
		{
			//PUSH THIS: dref
			map_info.Type=DREF_TO;
			map_info.Dst=dref;
			m_disassemblyStorage.AddMapInfo(&map_info);
			dref=get_next_dref_to(current_addr,dref);
		}

		//dref_from
		dref=get_first_dref_from(current_addr);
		while(dref!=BADADDR)
		{
			//PUSH THIS: next_drefs dref

			map_info.Type=DREF_FROM;
			map_info.Dst=dref;
			m_disassemblyStorage.AddMapInfo(&map_info);
			dref=get_next_dref_from(current_addr,dref);
		}

		if(found_branch)
		{
			bool is_positive_jmp=TRUE;
			if(
				current_itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
				current_itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
				current_itype == NN_jc ||                  // Jump if Carry (CF=1)
				current_itype == NN_jcxz ||                // Jump if CX is 0
				current_itype == NN_jecxz ||               // Jump if ECX is 0
				current_itype == NN_jrcxz ||               // Jump if RCX is 0
				current_itype == NN_je ||                  // Jump if Equal (ZF=1)
				current_itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
				current_itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
				current_itype == NN_jo ||                  // Jump if Overflow (OF=1)
				current_itype == NN_jp ||                  // Jump if Parity (PF=1)
				current_itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
				current_itype == NN_js ||                  // Jump if Sign (SF=1)
				current_itype == NN_jz ||                  // Jump if Zero (ZF=1)
				current_itype == NN_jmp ||                 // Jump
				current_itype == NN_jmpfi ||               // Indirect Far Jump
				current_itype == NN_jmpni ||               // Indirect Near Jump
				current_itype == NN_jmpshort ||            // Jump Short
				current_itype == NN_jpo ||                 // Jump if Parity Odd  (PF=0)
				current_itype == NN_jl ||                  // Jump if Less (SF!=OF)
				current_itype == NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
				current_itype == NN_jb ||                  // Jump if Below (CF=1)
				current_itype == NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
				current_itype == NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
				current_itype == NN_jnae ||                // Jump if Not Above or Equal (CF=1)
				current_itype == NN_jnb ||                 // Jump if Not Below (CF=0)
				current_itype == NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
				current_itype == NN_jnc ||                 // Jump if Not Carry (CF=0)
				current_itype == NN_jne ||                 // Jump if Not Equal (ZF=0)
				current_itype == NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
				current_itype == NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
				current_itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
				current_itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
				current_itype == NN_jno ||                 // Jump if Not Overflow (OF=0)
				current_itype == NN_jnp ||                 // Jump if Not Parity (PF=0)
				current_itype == NN_jns ||                 // Jump if Not Sign (SF=0)
				current_itype == NN_jnz                 // Jump if Not Zero (ZF=0)
			)
			{
				//map table
				//check last instruction whether it was positive or negative to tweak the map
				if(
						current_itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
						current_itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
						current_itype == NN_jc ||                  // Jump if Carry (CF=1)
						current_itype == NN_jcxz ||                // Jump if CX is 0
						current_itype == NN_jecxz ||               // Jump if ECX is 0
						current_itype == NN_jrcxz ||               // Jump if RCX is 0
						current_itype == NN_je ||                  // Jump if Equal (ZF=1)
						current_itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
						current_itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
						current_itype == NN_jo ||                  // Jump if Overflow (OF=1)
						current_itype == NN_jp ||                  // Jump if Parity (PF=1)
						current_itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
						current_itype == NN_js ||                  // Jump if Sign (SF=1)
						current_itype == NN_jz ||                  // Jump if Zero (ZF=1)
						current_itype == NN_jmp ||                 // Jump
						current_itype == NN_jmpfi ||               // Indirect Far Jump
						current_itype == NN_jmpni ||               // Indirect Near Jump
						current_itype == NN_jmpshort ||            // Jump Short
						current_itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
						current_itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
						current_itype == NN_jnb ||                 // Jump if Not Below (CF=0)
						current_itype == NN_jnbe                 // Jump if Not Below or Equal (CF=0 & ZF=0)						
					)
				{
					is_positive_jmp=TRUE;
				}else
				{
					is_positive_jmp=FALSE;
				}
			}

			vector<ea_t>::iterator cref_list_iter;
			//If Split Block
			//must be jmp,next block has only one cref_to
			if(cref_list.size() == 1 && current_itype == NN_jmp && InstructionCount>1)
			{
				cref_list_iter=cref_list.begin();
				ea_t next_block_addr=*cref_list_iter;
				
				//cref_to
				int cref_to_count=0;
				ea_t cref_to=get_first_cref_to(next_block_addr);
				while(cref_to!=BADADDR)
				{
					if(current_addr!=cref_to)
						cref_to_count++;
					cref_to=get_next_cref_to(next_block_addr,cref_to);
				}
				if(cref_to_count == 0)
				{
					//Merge it
					if(!first_block_end_address)
						first_block_end_address=current_addr+current_item_size;
					//next_block_addr should not be analyzed again next time.
					if(current_block_start_address!=StartEA)
					{
						WriteToLogFile(gLogFile,"%s: [AdditionallyAnalyzedBlocksIter] Set Analyzed %X~%X\n",__FUNCTION__,current_block_start_address,current_addr+current_item_size);
						AdditionallyAnalyzedBlocks.insert(pair<ea_t,ea_t>(current_block_start_address,current_addr+current_item_size));
					}
					if(current_block_start_address!=next_block_addr)
					{
						current_block_start_address=next_block_addr;
						WriteToLogFile(gLogFile,"%s: [AdditionallyAnalyzedBlocksIter] Set current_block_start_address=%X\n",__FUNCTION__,current_block_start_address);
						current_addr=next_block_addr;
						found_branch=FALSE;
						cref_list.clear();
						continue;
					}
				}
			}
			if(is_positive_jmp)
			{
				for(cref_list_iter=cref_list.begin();
					cref_list_iter!=cref_list.end();
					cref_list_iter++)
				{
					map_info.Type=CREF_FROM;
					map_info.Dst=*cref_list_iter;
					m_disassemblyStorage.AddMapInfo(&map_info);
				}
			}else
			{
				vector<ea_t>::reverse_iterator cref_list_iter;				
				for(cref_list_iter=cref_list.rbegin();
					cref_list_iter!=cref_list.rend();
					cref_list_iter++)
				{
					map_info.Type=CREF_FROM;
					map_info.Dst=*cref_list_iter;
					m_disassemblyStorage.AddMapInfo(&map_info);
				}
			}

			if(current_block_start_address!=StartEA)
			{
				WriteToLogFile(gLogFile,"%s: [AdditionallyAnalyzedBlocksIter] Set Analyzed %X~%X\n",__FUNCTION__,current_block_start_address,current_addr+current_item_size);
				AdditionallyAnalyzedBlocks.insert(pair<ea_t,ea_t>(current_block_start_address,current_addr+current_item_size));
			}

			if(first_block_end_address)
				return first_block_end_address;
			return current_addr+current_item_size;
		}
		current_addr+=current_item_size;
	}
	if(current_block_start_address!=StartEA)
	{
		WriteToLogFile(gLogFile,"%s: [AdditionallyAnalyzedBlocksIter] Set Analyzed %X~%X\n",__FUNCTION__,current_block_start_address,current_addr);
		AdditionallyAnalyzedBlocks.insert(pair<ea_t,ea_t>(current_block_start_address,current_addr));
	}
	WriteToLogFile(gLogFile,"%s: CmdArray size=%u\n",__FUNCTION__,pCmdArray->size());
	if(first_block_end_address)
		return first_block_end_address;
	return current_addr;
}

void IDAAnalyzer::AnalyzeIDADataByRegion(list <AddressRegion> *pAddressRegions, bool GatherCmdArray)
{
	if(!pAddressRegions)
		return;

	unordered_map <ea_t,ea_t> additionally_analyzed_blocks;

	for (list <AddressRegion>::iterator it = pAddressRegions->begin(); it != pAddressRegions->end(); it++)
	{
		ea_t startEA = (*it).startEA;
		ea_t endEA = (*it).endEA;
		
		WriteToLogFile(gLogFile,"Analyzing %X~%X\n",startEA,endEA);

		ea_t current_address;
		for (current_address = startEA; current_address<endEA;)
		{
			list <insn_t> CmdArray;
			flags_t Flag;
			
			ea_t next_address = AnalyzeBlock(current_address, endEA, &CmdArray, &Flag, additionally_analyzed_blocks);
			if(0)
			{
				unordered_map <op_t, OperandPosition, OpTypeHasher, OpTypeEqualFn> OperandsHash;
				multimap <OperandPosition,OperandPosition,OperandPositionCompareTrait> InstructionMap;
				unordered_map <ea_t,insn_t> InstructionHash;
				unordered_map <int,ea_t> FlagsHash;

				for(list <insn_t>::iterator CmdArrayIter=CmdArray.begin();CmdArrayIter!=CmdArray.end();CmdArrayIter++)
				{			
					UpdateInstructionMap(OperandsHash,FlagsHash,InstructionMap,InstructionHash,*CmdArrayIter);
				}
				
				list <insn_t> *NewCmdArray=ReoderInstructions(InstructionMap,InstructionHash);
				
				WriteToLogFile(gLogFile,"NewCmdArray=%X\n",NewCmdArray);

				if(NewCmdArray)
				{
					DumpBasicBlock(current_address, NewCmdArray, Flag, GatherCmdArray);
					delete NewCmdArray;
				}
			}else
			{
				DumpBasicBlock(current_address, &CmdArray, Flag, GatherCmdArray);
			}

			CmdArray.clear();

			if (current_address == next_address)
				break;

			current_address = next_address;
		}
	}
}

list <AddressRegion> GetMemberAddresses(ea_t StartAddress)
{
	ea_t current_addr;
	size_t current_item_size = 0;
	list <ea_t> AddressQueue;
	list <ea_t>::iterator AddressQueueIter;
	AddressQueue.push_back(StartAddress);
	unordered_set <ea_t> AddressHash;
	AddressHash.insert(StartAddress);

	list <AddressRegion> AddressRegions;

	for(
        AddressQueueIter = AddressQueue.begin();
        AddressQueueIter!=AddressQueue.end();
        AddressQueueIter++
    )
	{
		msg("Analyzing Address %X\n", *AddressQueueIter);
		ea_t block_StartAddress = *AddressQueueIter;

		for(current_addr=block_StartAddress;;current_addr+=current_item_size)
		{
			bool bEndOfBlock=FALSE;

            qstring op_buffer;
            print_insn_mnem(&op_buffer, current_addr);
			current_item_size=get_item_size(current_addr);

			if(!strnicmp(op_buffer.c_str(),"ret",3))
			{
				bEndOfBlock=TRUE;
			}

            insn_t insn;
            decode_insn(&insn, current_addr);

			ea_t cref=get_first_cref_from(current_addr);
			while(cref!=BADADDR)
			{
				if(
                    insn.itype == NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
                    insn.itype == NN_jae ||                 // Jump if Above or Equal (CF=0)
                    insn.itype == NN_jc ||                  // Jump if Carry (CF=1)
                    insn.itype == NN_jcxz ||                // Jump if CX is 0
                    insn.itype == NN_jecxz ||               // Jump if ECX is 0
                    insn.itype == NN_jrcxz ||               // Jump if RCX is 0
                    insn.itype == NN_je ||                  // Jump if Equal (ZF=1)
                    insn.itype == NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
					insn.itype == NN_jge ||                 // Jump if Greater or Equal (SF=OF)
					insn.itype == NN_jo ||                  // Jump if Overflow (OF=1)
					insn.itype == NN_jp ||                  // Jump if Parity (PF=1)
					insn.itype == NN_jpe ||                 // Jump if Parity Even (PF=1)
					insn.itype == NN_js ||                  // Jump if Sign (SF=1)
					insn.itype == NN_jz ||                  // Jump if Zero (ZF=1)
					insn.itype == NN_jmp ||                 // Jump
					insn.itype == NN_jmpfi ||               // Indirect Far Jump
					insn.itype == NN_jmpni ||               // Indirect Near Jump
					insn.itype == NN_jmpshort ||            // Jump Short
					insn.itype == NN_jpo ||                 // Jump if Parity Odd  (PF=0)
					insn.itype == NN_jl ||                  // Jump if Less (SF!=OF)
					insn.itype == NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
					insn.itype == NN_jb ||                  // Jump if Below (CF=1)
					insn.itype == NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
					insn.itype == NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
					insn.itype == NN_jnae ||                // Jump if Not Above or Equal (CF=1)
					insn.itype == NN_jnb ||                 // Jump if Not Below (CF=0)
					insn.itype == NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
					insn.itype == NN_jnc ||                 // Jump if Not Carry (CF=0)
					insn.itype == NN_jne ||                 // Jump if Not Equal (ZF=0)
					insn.itype == NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
					insn.itype == NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
					insn.itype == NN_jnl ||                 // Jump if Not Less (SF=OF)
					insn.itype == NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
					insn.itype == NN_jno ||                 // Jump if Not Overflow (OF=0)
					insn.itype == NN_jnp ||                 // Jump if Not Parity (PF=0)
					insn.itype == NN_jns ||                 // Jump if Not Sign (SF=0)
					insn.itype == NN_jnz                 // Jump if Not Zero (ZF=0)
				)
				{
					msg("Got Jump at %X\n",current_addr);
					if(AddressHash.find(cref) == AddressHash.end())
					{
						msg("Adding %X to queue\n",cref);
						AddressHash.insert(cref);
						AddressQueue.push_back(cref);
					}
					//cref is the next block position
					bEndOfBlock=TRUE;
				}
				cref=get_next_cref_from(current_addr,cref);
			}
			//cref_to
			cref=get_first_cref_to(current_addr+current_item_size);
			while(cref!=BADADDR)
			{
				if(current_addr!=cref)
				{
                    print_insn_mnem(&op_buffer, cref);
					
					if(
						!((ph.id == PLFM_386 || ph.id == PLFM_IA64) && (insn.itype == NN_call || insn.itype == NN_callfi || insn.itype == NN_callni)) ||
						!(ph.id == PLFM_ARM && (insn.itype == ARM_bl || insn.itype == ARM_blx1 || insn.itype == ARM_blx2)) ||
						!(ph.id == PLFM_MIPS && (insn.itype == MIPS_jal || insn.itype == MIPS_jalx))
					)
					{
						//End of block
						msg("Got End of Block at %X\n",current_addr);
						bEndOfBlock=TRUE;
					}
				}
				cref=get_next_cref_to(current_addr+current_item_size,cref);
			}
			if(bEndOfBlock)
			{	
				//jump to local block
				//block_StartAddress,current_addr+item_size is a block
				AddressRegion address_region;
				address_region.startEA = block_StartAddress;
				address_region.endEA = current_addr+current_item_size;
				AddressRegions.push_back(address_region);
				break;
			}
		}
	}

	/*
	list <AddressRegion>::iterator AddressRegionsIter;
	for(AddressRegionsIter=AddressRegions.begin();AddressRegionsIter!=AddressRegions.end();AddressRegionsIter++)
	{
		msg("Collected Addresses %X - %X\n",(*AddressRegionsIter).startEA,(*AddressRegionsIter).endEA);
	}
	*/
	return AddressRegions;
}

IDAAnalyzer::IDAAnalyzer(DisassemblyStorage& disassemblyStorage)
{
	m_disassemblyStorage = disassemblyStorage;
}

void IDAAnalyzer::AnalyzeIDAData(ea_t StartEA, ea_t EndEA, bool GatherCmdArray)
{
	FileInfo file_info;
	memset((char *)&file_info,0,sizeof(file_info));

	msg("Retrieving File Information\n");
	DWORD ComputerNameLen=sizeof(file_info.ComputerName);
	GetComputerName(file_info.ComputerName,&ComputerNameLen);
	DWORD UserNameLen=sizeof(file_info.UserName);
	GetUserName(file_info.UserName,&UserNameLen);

	char *input_file_path = NULL;

	char OriginalFilePath[1024]={0,};
	get_input_file_path(file_info.OriginalFilePath, sizeof(file_info.OriginalFilePath) - 1);
	m_disassemblyStorage.SetFileInfo(&file_info);

	ea_t saddr, eaddr;

	// Get the user selection
	int selected=0;
	if(StartEA!=0 && EndEA!=0)
	{
		selected=TRUE;
		saddr=StartEA;
		eaddr=EndEA;
	}else
	{
		//TODO: Porting selected= read_range_selection(&saddr,&eaddr);
	}

	printf("Sending Analyzed Information\n");
	list <AddressRegion> AddressRegions;
	if(selected)
	{
		func_t *cur_func_t=get_func(saddr);
		if(cur_func_t->start_ea == saddr)
		{
			//Collect all member addresses
			AddressRegions = GetMemberAddresses(saddr);
		}else
		{
			AddressRegion address_region;
			address_region.startEA=saddr;
			address_region.endEA=eaddr;
			AddressRegions.push_back(address_region);
		}
	}else
	{
		for(int n=0;n<get_segm_qty();n++)
		{
			segment_t *seg_p=getnseg(n);
			AddressRegion address_region;
			address_region.startEA=seg_p->start_ea;
			address_region.endEA=seg_p->end_ea;
			AddressRegions.push_back(address_region);
		}
	}

	AnalyzeIDADataByRegion(&AddressRegions, GatherCmdArray);	
	m_disassemblyStorage.EndAnalysis();
	msg("Sent All Analysis Informations\n");
}
