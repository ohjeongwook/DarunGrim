#include <windows.h>
#include "IDATracer.h"
#include "IDAUtils.h"
//#include "SocketOperation.h"
//#include "SharedSocket.h"
//#include "MapDrawerCOM.h"
//#include "WindowMessage.h"

#define DEBUG_LEVEL 0

enum {INTERESTING_OPERAND,INTERESTING_STACK_POS};
typedef struct _InterestingPoint_
{
	ea_t interested_address;
	int type;
	op_t operand;
	int stack_pos;
} InterestingPoint;

void DumpInterestingPointsInfo(list <InterestingPoint> InterestingPoints)
{
	list <InterestingPoint>::iterator interesting_points_iter;

	msg("     [Interesting Operands]\n");
	for(interesting_points_iter=InterestingPoints.begin();
	interesting_points_iter!=InterestingPoints.end();
	interesting_points_iter++)
	{
		if((*interesting_points_iter).type==INTERESTING_STACK_POS)
		{
			msg("          stack_pos: %d\n",(*interesting_points_iter).stack_pos);
		}else
		{
			DumpOptInfo((*interesting_points_iter).operand,"          ");
		}
	}
}

bool is_interesting_operand(op_t operand)
{
	if(operand.type==o_reg ||
		operand.type==o_displ ||
		operand.type==o_phrase ||
		(operand.type==o_mem && operand.hasSIB))
	{
		return true;
	}
	return false;
}


enum {
	r_eax,r_ecx,r_edx,r_ebx,
	r_esp,r_ebp,r_esi,r_edi,
	r_r8,r_r9,r_r10,r_r11,r_r12,r_r13,r_r14,r_r15,
	r_al,r_cl,r_dl,r_bl,
	r_ah,r_ch,r_dh,r_bh,
	r_spl,r_bpl,r_sil,r_dil,r_ip,
	r_es,r_cs,r_ss,r_ds,r_fs,r_gs
};

bool is_same_register(int reg1,int reg2)
{
	if(reg1==reg2)
		return true;

	if((reg1==r_al || reg1==r_ah)
		&& reg2==r_eax)
		return true;
	if(reg1==r_eax && 
		(reg2==r_al || reg2==r_ah)
	)
		return true;


	if((reg1==r_cl || reg1==r_ch)
		&& reg2==r_ecx)
		return true;
	if(reg1==r_ecx && 
		(reg2==r_cl || reg2==r_ch)
	)
		return true;

	if((reg1==r_dl || reg1==r_dh)
		&& reg2==r_edx)
		return true;
	if(reg1==r_edx && 
		(reg2==r_dl || reg2==r_dh)
	)
		return true;

	if((reg1==r_bl || reg1==r_bh)
		&& reg2==r_ebx)
		return true;
	if(reg1==r_ebx && 
		(reg2==r_bl || reg2==r_bh)
	)
		return true;
	return false;
}

enum {OP_T_NO_EFFECT,OP_T_EXACT_MATCH,OP_T_MEMBER_MATCH,OP_T_USED,OP_T_PARTIAL_MEMBER_MATCH};
char *gMatchTypeStr[]=
{
	"No Effect",
	"Exact Match",
	"Member Match",
	"Used",
	"Partial Member Match"
};

int CheckForOperandMatch
(
	ea_t search_this_address,
	op_t *p_search_this,

	ea_t search_here_address,
	op_t *p_search_here,

	int *p_leftover_reg
)
{
	*p_leftover_reg=-1;
	int match_type=OP_T_NO_EFFECT;
	if(p_search_this->type==o_reg)
	{
		if(p_search_here->type==o_reg)
		{
			if(is_same_register(p_search_this->reg,p_search_here->reg))
			{
				match_type=OP_T_EXACT_MATCH;
			}
		}else if(p_search_here->type==o_phrase)
		{
			if(is_same_register(p_search_this->reg,sib_base(*p_search_here)) ||
			is_same_register(p_search_this->reg,sib_index(*p_search_here))
			)
			{
				match_type=OP_T_USED;
			}
		}else if(p_search_here->type==o_displ)
		{
			if(is_same_register(p_search_this->reg,p_search_here->phrase))
			{
				match_type=OP_T_USED;
			}
		}
	}else if(p_search_this->type==o_displ || p_search_this->type==o_phrase)
	{
		if(p_search_here->type==o_reg)
		{
			if(p_search_here->reg!=4 && p_search_here->reg!=5)
			{
				if(p_search_this->hasSIB)
				{
					if(p_search_here->reg==sib_base(*p_search_this))
					{
						match_type=OP_T_PARTIAL_MEMBER_MATCH;
						if(sib_base(*p_search_this)!=sib_index(*p_search_this))
							*p_leftover_reg=sib_index(*p_search_this);

					}
					if(p_search_here->reg==sib_index(*p_search_this))
					{
						match_type=OP_T_PARTIAL_MEMBER_MATCH;
						*p_leftover_reg=sib_base(*p_search_this);
					}
				}
				else if(p_search_this->phrase==p_search_here->reg)
				{
					match_type=OP_T_MEMBER_MATCH;
				}
			}
		}else if(p_search_here->type==p_search_this->type)
		{
			if(
				p_search_this->phrase==p_search_here->phrase &&
				p_search_this->hasSIB==p_search_here->hasSIB &&
				sib_base(*p_search_this)==sib_base(*p_search_here) &&
				sib_index(*p_search_this)==sib_index(*p_search_here)
			)
			{
				if(p_search_this->phrase==4 &&
					sib_base(*p_search_this)==4 &&
					sib_index(*p_search_this)==4
				)
				{
					ua_ana0(search_this_address);
					member_t *p_this_stkvar=get_stkvar(
						*p_search_this,
						p_search_this->addr,
						NULL);

					ua_ana0(search_here_address);
					member_t *p_here_stkvar=get_stkvar(
						*p_search_here,
						p_search_here->addr,
						NULL);
					if(p_this_stkvar==p_here_stkvar)
					{
						match_type=OP_T_EXACT_MATCH;
					}					
				}else
				if(p_search_this->addr==p_search_here->addr)
					match_type=OP_T_EXACT_MATCH;
			}
		}
	}else if(p_search_this->type==o_mem)
	{
		if(p_search_here->type==o_reg)
		{
			if(p_search_here->reg!=4 && p_search_here->reg!=5)
			{
				if(p_search_this->hasSIB &&
					sib_index(*p_search_this)==p_search_here->reg
				)
				{
					match_type=OP_T_MEMBER_MATCH;
				}
			}
		}else if(p_search_here->type==o_mem)
		{
			if(p_search_this->hasSIB &&
				p_search_this->hasSIB==p_search_here->hasSIB &&
				sib_index(*p_search_this)==sib_index(*p_search_here)
			)
			{
				match_type=OP_T_EXACT_MATCH;
			}
		}
	}
	return match_type;
}

typedef struct _AnalysisElement_{
	ea_t block_addr;
	ea_t interested_address;
	int stack_pos;
	op_t operand;
} AnalysisElement;

struct hash_comp_structure
{
	inline size_t operator()(const AnalysisElement& x) const
	{
		return (size_t)x.block_addr;
	}

	bool operator()(const AnalysisElement & x,const AnalysisElement & y) const 
	{
		if(x.block_addr==y.block_addr)
			return true;
		return false;
	}
};

struct eq_structure
{
  bool operator()(AnalysisElement x,AnalysisElement y) const
  {
    return (x.block_addr==y.block_addr) && !memcmp(&x.operand,&y.operand,sizeof(x.operand));
  }
};

typedef hash_map <ea_t,char> CheckedAddressMapStruct,*PCheckedAddressMapStruct;
typedef hash_map <ea_t,char>::iterator CheckedAddressMapStructIterator;
typedef pair <ea_t,char> CheckedAddressMapStructPair;

void DumpTraceResultMapTree(void (*Callback)(int type,int level,ea_t parent_ea,char *disasm_line),multimap <ea_t,ea_t> *p_trace_result_map,ea_t parent_ea,int level,PCheckedAddressMapStruct p_checked_address_map)
{
	char buffer[1024];
	DWORD dwBytesWritten;
	if(p_checked_address_map->find(parent_ea)==p_checked_address_map->end())
	{
		p_checked_address_map->insert(CheckedAddressMapStructPair(parent_ea,1));	
	}else
	{
		//LogData: int level,ea_t parent_ea,int type=LOOP
		Callback(TRACE_TYPE_LOOP,level,parent_ea,"");
		return;
	}

	char disasm_buffer[100]={0,};
	generate_disasm_line(
		parent_ea,
		disasm_buffer,
		sizeof(disasm_buffer),
		0);
	tag_remove(disasm_buffer,disasm_buffer,sizeof(disasm_buffer));

	Callback(TRACE_TYPE_DISASM_LINE,level,parent_ea,disasm_buffer);
	multimap <ea_t,ea_t>::iterator trace_result_map_iter;
	ea_t last_ea=0L;
	for(
		trace_result_map_iter=p_trace_result_map->find(parent_ea);
		trace_result_map_iter!=p_trace_result_map->end();
		trace_result_map_iter++
	)
	{
		if(trace_result_map_iter->first==parent_ea &&
			last_ea!=trace_result_map_iter->second)
		{
			//LogData: level,parent_ea,char disasm_buffer,int type=DISASM_LINE
			last_ea=trace_result_map_iter->second;
			DumpTraceResultMapTree(Callback,
				p_trace_result_map,
				trace_result_map_iter->second,
				level+1,
				p_checked_address_map);
		}
	}

	CheckedAddressMapStructIterator checked_address_map_struct_iterator=p_checked_address_map->find(parent_ea);
	if(checked_address_map_struct_iterator!=p_checked_address_map->end())
	{
		p_checked_address_map->erase(checked_address_map_struct_iterator);
	}	
}

void DumpToFile(int type,int level,ea_t current_address,char *disasm_line)
{
	static HANDLE hFile=INVALID_HANDLE_VALUE;
	if(type==TRACE_TYPE_END)
	{
		if(hFile!=INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
			hFile=INVALID_HANDLE_VALUE;
		}
		return;
	}
	if(type==TRACE_TYPE_START)
	{
		char Filename[MAX_PATH+1];
		_snprintf(Filename,sizeof(Filename),"Trace-%.8x.txt",current_address);
		if(hFile==INVALID_HANDLE_VALUE)
		{
			hFile=CreateFile(Filename,   // file to open
							GENERIC_WRITE,         // open for reading
							FILE_SHARE_READ|FILE_SHARE_WRITE,      // share for reading and writing
							NULL,                 // default security
							CREATE_ALWAYS,        // existing file only
							FILE_ATTRIBUTE_NORMAL,// normal file
							NULL);                 // no attr. template
			 
			if (hFile==INVALID_HANDLE_VALUE) 
			{ 
				msg("Could not open file (error %d)\n",GetLastError());
				return;
			}
		}
		return;
	}
	if(type==TRACE_TYPE_DISASM_LINE && hFile!=INVALID_HANDLE_VALUE)
	{
		DWORD NumberOfBytesWritten;
		char Buffer[1024];
		for(int i=0;i<level;i++)
			Buffer[i]='\t';
		_snprintf(Buffer+level,sizeof(Buffer)-level,"%.8x: %s\r\n",current_address,disasm_line);
		WriteFile(
			hFile,
			Buffer,
			strlen(Buffer),
			&NumberOfBytesWritten,
			NULL);
		}
}

void DumpPlainDataToScreen(int type,int level,ea_t current_address,char *disasm_line)
{
	if(type==TRACE_TYPE_END)
	{
	}
	if(type==TRACE_TYPE_START)
	{
	}
	if(type==TRACE_TYPE_DISASM_LINE)
	{
		DWORD NumberOfBytesWritten;
		char Buffer[1024];
		for(int i=0;i<level;i++)
			Buffer[i]='\t';
		_snprintf(Buffer+level,sizeof(Buffer)-level,"%.8x: %s\r\n",current_address,disasm_line);
		msg("%s",Buffer);
	}
}

void DumpPlainData(ea_t root_ea,multimap <ea_t,ea_t> *p_trace_result_map,void (*Callback)(int type,int level,ea_t parent_ea,char *disasm_line))
{
	Callback(TRACE_TYPE_START,0,root_ea,NULL);
	CheckedAddressMapStruct checked_address_map;
	DumpTraceResultMapTree(Callback,p_trace_result_map,root_ea,0,&checked_address_map);
	Callback(TRACE_TYPE_END,0,0,NULL);
	checked_address_map.clear();
}

#define WM_DRAW_DATA WM_USER+1
LRESULT MessageWndProc(HWND wnd,UINT message,WPARAM wp,LPARAM lp)
{
	switch (message)
	{
		case WM_DRAW_DATA:
			msg("Get the data: %x\n",wp);
			jumpto((ea_t)wp);
			break;
		default:
			return DefWindowProc(wnd, message, wp, lp);
	}
	return 0;	
}

typedef struct _AddressInformation_
{
	DWORD CurrentAddress;
	char *FunctionName;
} AddressInformation;

/*
void DumpMapDataToScreen(char type,PBYTE data,int length)
{
	static DWORD CurrentAddress;
	static char *FunctionName;
	hash_multimap

	switch(type)
	{
		case TYPE_CURRENT_ADDRESS:
			CurrentAddress=*(DWORD *)data;
			break;
		case TYPE_FUNCTION_NAME:
			FunctionName=(char *)data;
			break;
		case TYPE_DISASSEMBLY:
			{
				char *Disassembly=(char *)data;
				msg("%p %s %s\n",CurrentAddress,FunctionName,Disassembly);
			}
			break;
		case TYPE_MAP_DATA:
			{
				ea_t *p_addresses=(ea_t *)data;
				msg("%p -> %p\n",p_addresses[1],p_addresses[0]);
			}
			break;
		case TYPE_END:
			break;
	}
}*/

void DumpMapData(HANDLE hFile,ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map,void (*Callback)(char type,PBYTE data,int length))
{
	hash_set <ea_t> addresses;
	multimap <ea_t,ea_t>::iterator trace_result_map_iter;
	for(
		trace_result_map_iter=p_trace_result_map->begin();
		trace_result_map_iter!=p_trace_result_map->end();
		trace_result_map_iter++
	)
	{
		addresses.insert(trace_result_map_iter->first);
		addresses.insert(trace_result_map_iter->second);
	}

	char Buffer[1024];
	DWORD NumberOfBytesWritten;
	//_snprintf(Buffer,sizeof(Buffer),"digraph g { graph [ rankdir = \"TB\" bgcolor=\"#292941\"]; node [style=filled fontsize=7 fillcolor=\"#292941\" fontcolor=\"#ffffff\";];");
	_snprintf(Buffer,sizeof(Buffer),"digraph g { graph [ rankdir = \"TB\"]; node [style=filled fontsize=7 fontname=\"Bitstream Vera Sans\"];");
	if(hFile!=INVALID_HANDLE_VALUE)
	{
			WriteFile(
			hFile,
			(LPCVOID)Buffer,
			strlen(Buffer),
			&NumberOfBytesWritten,
			NULL
		);
	}

	hash_set <ea_t>::iterator addresses_iter;
	for(
		addresses_iter=addresses.begin();
		addresses_iter!=addresses.end();
		addresses_iter++
	)
	{
		DWORD current_address=*addresses_iter;
		if(Callback)
		{
			Callback(TYPE_CURRENT_ADDRESS,(PBYTE)&current_address,sizeof(current_address)); 
		}

		char func_name_buffer[100]={0,};
		get_func_name(current_address,func_name_buffer,sizeof(func_name_buffer));		
		if(Callback)
		{
			Callback(TYPE_FUNCTION_NAME,(PBYTE)func_name_buffer,strlen(func_name_buffer)+1);
		}

		char disasm_buffer[100]={0,};
		generate_disasm_line(
			current_address,
			disasm_buffer,
			sizeof(disasm_buffer),
			0);
		tag_remove(disasm_buffer,disasm_buffer,sizeof(disasm_buffer));
		if(Callback)
		{
			Callback(TYPE_DISASSEMBLY,(PBYTE)disasm_buffer,strlen(disasm_buffer)+1);
		}else
		{
			_snprintf(Buffer,sizeof(Buffer),"\"%p\" [label=\"{%s(%x)|%s}\"\nshape=\"record\"\n];\n",current_address,func_name_buffer,current_address,disasm_buffer);
			if(hFile!=INVALID_HANDLE_VALUE)
			{
					WriteFile(
					hFile,
					(LPCVOID)Buffer,
					strlen(Buffer),
					&NumberOfBytesWritten,
					NULL
				);
			}
		}
	}
	for(
		trace_result_map_iter=p_trace_result_map->begin();
		trace_result_map_iter!=p_trace_result_map->end();
		trace_result_map_iter++
	)
	{
		ea_t addresses[2]={trace_result_map_iter->first,trace_result_map_iter->second}; //dst,src
		//find something doesn't have src
		
		if(Callback)
		{
			Callback(TYPE_MAP_DATA,(PBYTE)addresses,sizeof(addresses)); 
		}else
		{
			_snprintf(Buffer,sizeof(Buffer),"\"%p\" -> \"%p\"\n",addresses[1],addresses[0]);
			if(hFile!=INVALID_HANDLE_VALUE)
			{
					WriteFile(
					hFile,
					(LPCVOID)Buffer,
					strlen(Buffer),
					&NumberOfBytesWritten,
					NULL
				);
			}
		}
	}
	if(Callback)
	{
		Callback(TYPE_END,(PBYTE)"",1); 
	}
	_snprintf(Buffer,sizeof(Buffer),"}");
	if(hFile!=INVALID_HANDLE_VALUE)
	{
			WriteFile(
			hFile,
			(LPCVOID)Buffer,
			strlen(Buffer),
			&NumberOfBytesWritten,
			NULL
		);
	}
}

void DumpMapDataByFilename(char *filename,ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map,void (*Callback)(char type,PBYTE data,int length))
{
	HANDLE hFile=CreateFile(filename, // file to create
		GENERIC_WRITE, // open for writing
		0, // do not share
		NULL, // default security
		CREATE_ALWAYS, // overwrite existing
		FILE_ATTRIBUTE_NORMAL | // normal file
		NULL, // asynchronous I/O
		NULL); // no attr. template
	if(hFile==INVALID_HANDLE_VALUE)
	{ 
		msg("Could not open file(%s) (error %d)\n",filename,GetLastError());
		return;
	}
	DumpMapData(hFile,current_ea,p_trace_result_map,Callback);
	CloseHandle(hFile);
}

void DumpRoots(HANDLE hFile,ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map)
{
	hash_set <ea_t> addresses;
	multimap <ea_t,ea_t>::iterator trace_result_map_iter;
	for(
		trace_result_map_iter=p_trace_result_map->begin();
		trace_result_map_iter!=p_trace_result_map->end();
		trace_result_map_iter++
	)
	{
		addresses.insert(trace_result_map_iter->first);
		addresses.insert(trace_result_map_iter->second);
	}

	hash_set <ea_t>::iterator addresses_iter;
	for(
		addresses_iter=addresses.begin();
		addresses_iter!=addresses.end();
		addresses_iter++
	)
	{
		ea_t current_address=(*addresses_iter);
		if(p_trace_result_map->find(current_address)==p_trace_result_map->end())
		{
			char func_name_buffer[100]={0,};
			get_func_name(current_address,func_name_buffer,sizeof(func_name_buffer));		
			char disasm_buffer[100]={0,};
			generate_disasm_line(
				current_address,
				disasm_buffer,
				sizeof(disasm_buffer),
				0);
			tag_remove(disasm_buffer,disasm_buffer,sizeof(disasm_buffer));
			char Buffer[1024];
			DWORD NumberOfBytesWritten;
			_snprintf(Buffer,sizeof(Buffer),"%p %s %s\r\n",current_address,func_name_buffer,disasm_buffer);

			if(hFile!=INVALID_HANDLE_VALUE)
			{
				WriteFile(
					hFile,
					(LPCVOID)Buffer,
					strlen(Buffer),
					&NumberOfBytesWritten,
					NULL
				);
			}else
			{
				msg("%s",Buffer);
			}
		}		
	}
}

void RecordMatching(
	list <InterestingPoint> *pInterestingPoints,
	int match_type,
	ea_t interested_address,
	ea_t current_address,
	op_t *p_interested_operand,
	multimap <ea_t,ea_t> *pTraceResultMap
)
{
	
	//Matching is Found on current current_address
#if DEBUG_LEVEL > 1
	msg("===========================================================\n");
	msg("Matched Address(Interested Address=%x)\n",interested_address);
	/*msg("(%s-%x)\n",
	ph.instruc[cmd.itype].name,
	ph.instruc[cmd.itype].feature);
	*/
	static char disasm_buffer[100]={0,};
	generate_disasm_line(
		current_address,
		disasm_buffer,
		sizeof(disasm_buffer),
		0);
	tag_remove(disasm_buffer,disasm_buffer,sizeof(disasm_buffer));

	msg("%.8x: %s\n",current_address,disasm_buffer);
	msg("       Operands:\n");
	for(int i=0;cmd.Operands[i].type!=o_void;i++)
	{
		msg("          ");
		DumpCurrentOptInfo(current_address,i);
	}					
	if(match_type>0)
	{
		msg(">>>> Match Type=%s\n",gMatchTypeStr[match_type]);
		if(p_interested_operand)
			DumpOptInfo(*p_interested_operand,"        Interesting operand: ");
		//DumpOptInfo(cmd.Operands[matched_operand],"        Matched operand: ");
	}
#endif

	//Record Matching Info
	//interested_address -> address
	if(interested_address!=0)
		pTraceResultMap->insert(pair <ea_t,ea_t>(interested_address,current_address));
	//reconstruct InterestingOperands
	InterestingPoint interesting_point;
	if(cmd.itype==NN_xor && cmd.Operands[0].reg==cmd.Operands[1].reg)
	{
		//don't add anything,this is dead end
	}
	else if(cmd.itype==NN_pop)
	{
		//
		interesting_point.type=INTERESTING_STACK_POS;
		interesting_point.stack_pos=0;
		interesting_point.interested_address=current_address;
		pInterestingPoints->push_back(interesting_point);
	}else
	{
		if(ph.instruc[cmd.itype].feature&CF_USE1 && 
			is_interesting_operand(cmd.Operands[0]))
		{
			interesting_point.type=INTERESTING_OPERAND;
			interesting_point.interested_address=current_address;
			memcpy((void *)&interesting_point.operand,(void *)&cmd.Operands[0],sizeof(op_t));
			pInterestingPoints->push_back(interesting_point);
		}
		if(ph.instruc[cmd.itype].feature&CF_USE2 && 
			is_interesting_operand(cmd.Operands[1]))
		{
			interesting_point.type=INTERESTING_OPERAND;
			interesting_point.interested_address=current_address;
			memcpy((void *)&interesting_point.operand,(void *)&cmd.Operands[1],sizeof(op_t));
			pInterestingPoints->push_back(interesting_point);
		}
#if DEBUG_LEVEL > 2
		msg("     *** Updated interesting Operands>>\n");
		DumpInterestingPointsInfo(*pInterestingPoints);
#endif
	}
}

multimap <ea_t,ea_t> *TraceVariable(ea_t start_address,op_t operand,bool b_trace_up,bool b_trace_passive_usage)
{
	multimap <ea_t,ea_t> *pTraceResultMap=new multimap <ea_t,ea_t>;


	multimap <ea_t,ea_t> block_branch_map;
	multimap <ea_t,AnalysisElement> AnalyzedBlocksMap;
	queue <AnalysisElement> BlocksToAnalyze;
	
	AnalysisElement analysis_element;
	analysis_element.block_addr=start_address;
	ua_ana0(start_address);
	analysis_element.stack_pos=-1;
	analysis_element.interested_address=0;
	memcpy((void *)&analysis_element.operand,&operand,sizeof(op_t));

	BlocksToAnalyze.push(analysis_element);
	AnalyzedBlocksMap.insert(pair <ea_t,AnalysisElement>(analysis_element.block_addr,analysis_element));

	for(;
		!BlocksToAnalyze.empty();
		BlocksToAnalyze.pop())
	{
		list <InterestingPoint> InterestingPoints;
		list <InterestingPoint>::iterator interesting_points_iter;

		AnalysisElement& analysis_element=BlocksToAnalyze.front();
		ea_t block_start_address=analysis_element.block_addr;
		ea_t current_address=block_start_address;

		InterestingPoint interesting_point;
		interesting_point.interested_address=analysis_element.interested_address;
		if(analysis_element.stack_pos>=0)
		{
			interesting_point.type=INTERESTING_STACK_POS;
			interesting_point.stack_pos=analysis_element.stack_pos;
		}else
		{
			interesting_point.type=INTERESTING_OPERAND;
			memcpy((void *)&interesting_point.operand,(void *)&analysis_element.operand,sizeof(op_t));
		}
		InterestingPoints.clear();
		InterestingPoints.push_back(interesting_point);
#if DEBUG_LEVEL > 2
		msg(">>>[Analyzing Block: %x]<<<<\n",block_start_address);
		DumpInterestingPointsInfo(InterestingPoints);
#endif

		//Scan Block for operand/stack pos matching until we get to branch
		while(current_address>0L) //while previous current_address exists
		{
			list <InterestingPoint> NewInterestingPoints;
			if(ua_ana0(current_address)>0)
			{
				//Matching for register/memory/...
				ea_t interested_address=0L;
				int match_type=-1;
				int matched_operand=0;
				bool match_found=false;
				/*******************************************************************************/
				/****************                 Do the match              ********************/
				/*******************************************************************************/
				for(interesting_points_iter=InterestingPoints.begin();
					interesting_points_iter!=InterestingPoints.end();
					interesting_points_iter++)
				{
					int erase=false;
					if(b_trace_up)
					{
						if((*interesting_points_iter).type==INTERESTING_STACK_POS)
						{
							if(cmd.itype==NN_push)
							{
								if((*interesting_points_iter).stack_pos==0)
								{
									//found!
									erase=true;
									match_found=true;
									matched_operand=0;
									RecordMatching(&NewInterestingPoints,match_type,(*interesting_points_iter).interested_address,current_address,NULL,pTraceResultMap);
								}else{
									(*interesting_points_iter).stack_pos--;
								}
							}else if(cmd.itype==NN_pop)
							{
								(*interesting_points_iter).stack_pos++;
							}
						}else
						if((*interesting_points_iter).type==INTERESTING_OPERAND)
						{
							int leftover_reg;
							//OP_T_NO_EFFECT,
							//OP_T_EXACT_MATCH,
							//OP_T_MEMBER_MATCH,
							//OP_T_USED
							//Check for CALL Result
							if(cmd.itype==NN_call ||
								cmd.itype==NN_callfi ||
								cmd.itype==NN_callni)
							{
								op_t fake_op_t;
								memset(&fake_op_t,0,sizeof(op_t));
								fake_op_t.type=o_reg;
								fake_op_t.reg=r_eax;
								match_type=
									CheckForOperandMatch(
										(*interesting_points_iter).interested_address,
										&((*interesting_points_iter).operand),
										current_address,
										&fake_op_t,
										&leftover_reg
										);	
								if(
									match_type!=OP_T_NO_EFFECT &&
									match_type!=OP_T_USED
								)
								{
									match_found=true;
									matched_operand=0;
									if(match_type==OP_T_EXACT_MATCH || match_type==OP_T_MEMBER_MATCH || match_type==OP_T_PARTIAL_MEMBER_MATCH)
									{
										erase=true;
									}
									if(match_type==OP_T_PARTIAL_MEMBER_MATCH)
									{
										InterestingPoint interesting_point;
										interesting_point.interested_address=(*interesting_points_iter).interested_address;
										interesting_point.type=INTERESTING_OPERAND;
										interesting_point.operand.type=o_reg;
										interesting_point.operand.reg=leftover_reg;
										NewInterestingPoints.push_back(interesting_point);
									}
									RecordMatching(&NewInterestingPoints,match_type,(*interesting_points_iter).interested_address,current_address,NULL,pTraceResultMap);
								}
							}
							////////////////////////
							
							match_type=
								CheckForOperandMatch(
									(*interesting_points_iter).interested_address,
									&((*interesting_points_iter).operand),
									current_address,
									&cmd.Operands[0],
									&leftover_reg
									);
							if(current_address==start_address)
							{
								//msg("Start Pos(%x) Match type is %x\n",start_address,match_type);
							}
	
							if(
								match_type!=OP_T_NO_EFFECT &&
								match_type!=OP_T_USED &&
								(
									(b_trace_passive_usage || ph.instruc[cmd.itype].feature&CF_CHG1) 
								 	||
									current_address==start_address
								)
							)
							{
								match_found=true;
								matched_operand=0;
								if(match_type==OP_T_EXACT_MATCH || match_type==OP_T_MEMBER_MATCH || match_type==OP_T_PARTIAL_MEMBER_MATCH)
								{
									erase=true;
								}
								if(match_type==OP_T_PARTIAL_MEMBER_MATCH)
								{
									InterestingPoint interesting_point;
									interesting_point.interested_address=(*interesting_points_iter).interested_address;
									interesting_point.type=INTERESTING_OPERAND;
									interesting_point.operand.type=o_reg;
									interesting_point.operand.reg=leftover_reg;
									NewInterestingPoints.push_back(interesting_point);
								}
								RecordMatching(&NewInterestingPoints,match_type,(*interesting_points_iter).interested_address,current_address,NULL,pTraceResultMap);
							}
							if(b_trace_passive_usage && !match_found)
							{
								match_type=
									CheckForOperandMatch(
										(*interesting_points_iter).interested_address,
										&((*interesting_points_iter).operand),
										current_address,
										&cmd.Operands[1],
										&leftover_reg
										);
								if(match_type==OP_T_EXACT_MATCH)
								{
									match_found=true;
									matched_operand=1;
									RecordMatching(&NewInterestingPoints,match_type,(*interesting_points_iter).interested_address,current_address,&(*interesting_points_iter).operand,pTraceResultMap);
								}							
							}
						}
					}//if(b_trace_up)
					else
					{
						if((*interesting_points_iter).type==INTERESTING_STACK_POS)
						{
						}else
						if((*interesting_points_iter).type==INTERESTING_OPERAND)
						{
							//OP_T_NO_EFFECT,
							//OP_T_EXACT_MATCH,
							//OP_T_MEMBER_MATCH,
							//OP_T_USED
							int leftover_reg;
							match_type=
								CheckForOperandMatch(
									(*interesting_points_iter).interested_address,
									&cmd.Operands[1],
									current_address,
									&((*interesting_points_iter).operand),
									&leftover_reg
									);
	
							if(
								match_type!=OP_T_NO_EFFECT &&
								match_type!=OP_T_USED &&
								current_address==start_address
							)
							{
								match_found=true;
								matched_operand=0;
								if(match_type==OP_T_EXACT_MATCH || match_type==OP_T_MEMBER_MATCH || match_type==OP_T_PARTIAL_MEMBER_MATCH)
								{
									erase=true;
								}
								if(match_type==OP_T_PARTIAL_MEMBER_MATCH)
								{
									InterestingPoint interesting_point;
									interesting_point.interested_address=(*interesting_points_iter).interested_address;
									interesting_point.type=INTERESTING_OPERAND;
									interesting_point.operand.type=o_reg;
									interesting_point.operand.reg=leftover_reg;
									NewInterestingPoints.push_back(interesting_point);
								}
								RecordMatching(&NewInterestingPoints,match_type,(*interesting_points_iter).interested_address,current_address,NULL,pTraceResultMap);
							}
							if(!match_found /*&&
								(*interesting_points_iter).operand.type!=o_reg*/)
							{
								match_type=
									CheckForOperandMatch(
										(*interesting_points_iter).interested_address,
										&cmd.Operands[0],
										current_address,
										&((*interesting_points_iter).operand),
										&leftover_reg
										);
								if(match_type==OP_T_EXACT_MATCH)
								{
									if( ph.instruc[cmd.itype].feature&CF_CHG1)
									{
										erase=true;
									}
									match_found=true;
									matched_operand=1;
									RecordMatching(&NewInterestingPoints,match_type,(*interesting_points_iter).interested_address,current_address,&(*interesting_points_iter).operand,pTraceResultMap);
								}							
							}
						}						
					}
					if(!erase)
					{
						NewInterestingPoints.push_back(*interesting_points_iter);
					}
				}
			}
			InterestingPoints.clear();
			InterestingPoints=NewInterestingPoints;
			NewInterestingPoints.clear();


			/*******************************************************************************/
			/****************Transfer Interested Arguments to Next Block********************/
			/*******************************************************************************/

			bool found_branch=false;
			bool found_flow=false;

			xrefblk_t xb;
			bool (xrefblk_t::*first_func)(ea_t from,int flags);
			bool (xrefblk_t::*next_func)(void);
				
			if(b_trace_up)
			{
				first_func=&xrefblk_t::first_to;
				next_func=&xrefblk_t::next_to;
			}else
			{
				first_func=&xrefblk_t::first_from;
				next_func=&xrefblk_t::next_from;
			}				
			// Loop through all cross references
			for (bool res=(xb.*first_func)(current_address,XREF_ALL); res; res=(xb.*next_func)())
			{
#if DEBUG_LEVEL > 5
				msg("XREF> %a->%a Type: %d,IsCode: %d\n",xb.from,xb.to,xb.type,xb.iscode);
#endif
				if( //Jumps and Calls?
					xb.type==fl_JF || 
					xb.type==fl_JN ||
					xb.type==fl_CF  ||
					xb.type==fl_CN
				)
				{
					found_branch=true;
				}
				if(xb.type==fl_F)
				{
					found_flow=true;
				}
			}
			for(bool res=(xb.*first_func)(current_address,XREF_ALL); res; res=(xb.*next_func)())
			{
				if(found_branch)
				{
					block_branch_map.insert(pair <ea_t,ea_t> (block_start_address,xb.from));

					for(interesting_points_iter=InterestingPoints.begin();
						interesting_points_iter!=InterestingPoints.end();
						interesting_points_iter++)
					{
						if((*interesting_points_iter).type==INTERESTING_STACK_POS)
						{
							AnalysisElement analysis_element;
							analysis_element.block_addr=xb.from;
							analysis_element.interested_address=0;
							analysis_element.stack_pos=(*interesting_points_iter).stack_pos;
							memset(&analysis_element.operand,0,sizeof(analysis_element.operand));
							multimap <ea_t,AnalysisElement>::iterator AnalyzedBlocksMap_iterator;
							bool found=false;
							for(
								AnalyzedBlocksMap_iterator=AnalyzedBlocksMap.find(analysis_element.block_addr);
								AnalyzedBlocksMap_iterator!=AnalyzedBlocksMap.end() && AnalyzedBlocksMap_iterator->first==analysis_element.block_addr;
								AnalyzedBlocksMap_iterator++
							)
							{
								if(!memcmp(&AnalyzedBlocksMap_iterator->second,&analysis_element,sizeof(AnalysisElement)))
								{
									found=true;
									break;
								}
							}
							if(!found)
							{
								//queuing here
								AnalyzedBlocksMap.insert(pair <ea_t,AnalysisElement>(analysis_element.block_addr,analysis_element));
								analysis_element.interested_address=(*interesting_points_iter).interested_address;
								BlocksToAnalyze.push(analysis_element);								
							}
						}else
						if((* interesting_points_iter).type==INTERESTING_OPERAND)
						{
							AnalysisElement analysis_element;
							analysis_element.block_addr=xb.from;
							analysis_element.stack_pos=-1;
							analysis_element.interested_address=0;
							memcpy((void *)&analysis_element.operand,(void *)&(*interesting_points_iter).operand,sizeof(op_t));
							
							bool stack_register_over_call=false;
							bool found_in_argument=true;
							//Tracing stack variable(with base of sp/bp), when we meet fl_C*(call *)
							if(
								(xb.type==fl_CF  || xb.type==fl_CN ) &&
								(analysis_element.operand.reg==5/*bp*/ ||
								analysis_element.operand.reg==4/*sp*/)
							)
							{
								found_in_argument=false;
								if(analysis_element.operand.type==o_reg)
									stack_register_over_call=true;
								ua_ana0((*interesting_points_iter).interested_address);
								member_t *p_stkvar=get_stkvar(
									analysis_element.operand,
									analysis_element.operand.addr,
									NULL);
								if(p_stkvar)
								{
#if DEBUG_LEVEL > 3
									DumpOptInfo(analysis_element.operand,"Searching For Stack Variable Location: ");
									char member_name[40];
									get_struc_name(p_stkvar->id,member_name,sizeof(member_name));
									msg("p_stkvar->id=%d(%s)\n",p_stkvar->id,member_name);
#endif
									struc_t *p_struc=get_frame(current_address);
									if(p_struc)
									{
										int arg_pos=-1;
										for(size_t mem_i=0;mem_i<p_struc->memqty;mem_i++)
										{
											member_t *p_member=&p_struc->members[mem_i];
											if(p_member->flag==0x400)
											{
												arg_pos=0;
												continue;
											}
											char struc_name[40];
											get_struc_name(p_member->id,struc_name,sizeof(struc_name));
	#if DEBUG_LEVEL > 4
											msg("Stack Variable %s: member_id=%d (arg_pos=%d) soff(%d)-eoff(%d) flag=%x",
												struc_name,
												p_member->id,
												arg_pos,
												p_member->soff,
												p_member->eoff,
												p_member->flag);
	#endif
											if(p_stkvar==p_member)
											{
	#if DEBUG_LEVEL > 4
												msg(" [Matched]\n");
	#endif
												found_in_argument=true;
												analysis_element.stack_pos=arg_pos;
												break;
											}
	#if DEBUG_LEVEL > 4
											msg("\n");
	#endif
											if(arg_pos>=0)
												arg_pos++;
										}
									}
								}
							}
							if(found_in_argument)
							{
								multimap <ea_t,AnalysisElement>::iterator analyzed_blocks_map_iterator;
								bool found=false;
								for(analyzed_blocks_map_iterator=AnalyzedBlocksMap.find(analysis_element.block_addr);
									analyzed_blocks_map_iterator!=AnalyzedBlocksMap.end() && analyzed_blocks_map_iterator->first==analysis_element.block_addr;
									analyzed_blocks_map_iterator++
								)
								{
									if(!memcmp(&analyzed_blocks_map_iterator->second,&analysis_element,sizeof(AnalysisElement)))
									{
										found=true;
										break;
									}
								}
								if(!found && !stack_register_over_call)
								{
									//queuing here
									AnalyzedBlocksMap.insert(pair <ea_t,AnalysisElement>(analysis_element.block_addr,analysis_element));
									analysis_element.interested_address=(*interesting_points_iter).interested_address;
									BlocksToAnalyze.push(analysis_element);
								}
							}
						}
					}
					/*
					if(xb.type==fl_CF  || xb.type==fl_CN)
						return;
					*/
				}else //not found branch, one way flow
				if(xb.type==fl_F)
				{
					if(b_trace_up)
					{
						current_address=xb.from;
					}else{
						current_address=xb.to;
					}
				}
			}
			if(found_branch)
				break;
			if(!found_flow)
				break;
		}// while(current_address>0L)
		if(pTraceResultMap->size()>5000)
			break;
	}
	return pTraceResultMap;
}

