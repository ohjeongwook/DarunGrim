#pragma warning(disable:4819)

#define __X64__
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <frame.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <struct.hpp>
#include <allins.hpp>
#include <auto.hpp>
#include <range.hpp>

#include "IDAVerifier.h"

bool IsValidFunctionStart(ea_t address)
{
	int cref_to_count=0;
	int fcref_to_count=0;

	ea_t cref=get_first_fcref_to(address);
	while(cref!=BADADDR)
	{
		cref_to_count++;

        insn_t insn;
        decode_insn(&insn, cref);

		if(!(insn.itype==NN_call || insn.itype==NN_callfi || insn.itype==NN_callni))
		{
			return false;
		}
		cref=get_next_fcref_to(address,cref);
	}

	return true;
}

ea_t GetBlockEnd(ea_t address)
{
	while(address= next_that(address, BADADDR, f_is_code, NULL))
	{
		if(address == BADADDR)
			break;
		ea_t fcref = get_first_fcref_to(address);
		if(fcref != BADADDR)
			break;
	}
	return address;
}

int ConnectBrokenFunctionChunk(ea_t address)
{
	int connected_links_count=0;
	func_t *func=get_func(address);
	qstring function_name;
	get_short_name(&function_name, address);

	bool is_function=false;
	bool AddFunctionAsMemberOfFunction=false;

	ea_t cref=get_first_cref_to(address);
	while(cref!=BADADDR)
	{
		func_t *cref_func=get_func(cref);
		if(cref_func!=func)
		{
            insn_t insn;
            decode_insn(&insn, cref);
			if(insn.itype==NN_call || insn.itype==NN_callfi || insn.itype==NN_callni)
			{
				is_function=true;
				break;
			}
		}
		cref=get_next_cref_to(address,cref);
	}

	msg("ConnectBrokenFunctionChunk: %s %s\n", function_name.c_str(), is_function? "is function": "is not function" );

	if(!is_function)
	{
		if(func)
			del_func(address);	
		cref=get_first_cref_to(address);
		while(cref!=BADADDR)
		{
			func_t *cref_func=get_func(cref);
			if(cref_func)
			{
				qstring cref_function_name;
                get_func_name(&cref_function_name, cref);

				msg("Adding Location %s(%X) To Function Member Of %s(%X:%X)\n", function_name.c_str(), address, cref_function_name.c_str(), cref_func->start_ea, cref);

				append_func_tail(cref_func,address,GetBlockEnd(address));
				connected_links_count++;
			}
			cref=get_next_cref_to(address,cref);
		}
	}else if(AddFunctionAsMemberOfFunction)
	{
		cref=get_first_cref_to(address);
		while(cref!=BADADDR)
		{
            insn_t insn;
            decode_insn(&insn, cref);
			if(!(insn.itype==NN_call || insn.itype==NN_callfi || insn.itype==NN_callni))
			{
				func_t *cref_func=get_func(cref);
				if(cref_func)
				{
					qstring cref_function_name;
					get_func_name(&cref_function_name, cref);
					msg("Adding Function %s(%X) To Function Member Of %s(%X:%X)\n",function_name,address,cref_function_name.c_str(), cref_func->start_ea, cref);

					append_func_tail(cref_func,address,GetBlockEnd(address));
					connected_links_count++;
				}
			}
			cref=get_next_cref_to(address,cref);
		}
	}
	return connected_links_count;
}

void FindInvalidFunctionStartAndConnectBrokenFunctionChunk()
{
	int connected_links_count=0;
	do
	{
		connected_links_count=0;
		for(size_t i=0;i<get_func_qty();i++)
		{
			func_t *f=getn_func(i);
			if(!IsValidFunctionStart(f->start_ea))
			{
				qstring function_name;
				get_short_name(&function_name, f->start_ea);

				msg("Found invalid function: %s\n", function_name.c_str());
				connected_links_count+=ConnectBrokenFunctionChunk(f->start_ea);
			}		
		}
	}while(connected_links_count>0);
}