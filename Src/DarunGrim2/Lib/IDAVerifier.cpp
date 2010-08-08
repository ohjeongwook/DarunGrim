#pragma warning(disable:4819)
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
#include <area.hpp>

#include "IDAVerifier.h"

bool IsValidFunctionStart(ea_t address)
{
	int cref_to_count=0;
	int fcref_to_count=0;

	ea_t cref=get_first_fcref_to(address);
	while(cref!=BADADDR)
	{
		cref_to_count++;
		char op_buffer[40]={0,};
		ua_mnem(cref,op_buffer,sizeof(op_buffer));

		if(!(cmd.itype==NN_call || cmd.itype==NN_callfi || cmd.itype==NN_callni))
		{
			return false;
		}
		cref=get_next_fcref_to(address,cref);
	}

	return true;
}

ea_t GetBlockEnd(ea_t address)
{
	while(address=nextthat(address,BADADDR,f_isCode,NULL))
	{
		if(address==BADADDR)
			break;
		ea_t fcref=get_first_fcref_to(address);
		if(fcref!=BADADDR)
			break;
	}
	return address;
}

int ConnectBrokenFunctionChunk(ea_t address)
{
	int connected_links_count=0;
	func_t *func=get_func(address);
	char function_name[1024]={0,};
	get_func_name(address,function_name,sizeof(function_name));

	bool is_function=false;
	bool AddFunctionAsMemberOfFunction=false;

	ea_t cref=get_first_cref_to(address);
	while(cref!=BADADDR)
	{
		func_t *cref_func=get_func(cref);
		if(cref_func!=func)
		{
			char op_buffer[40]={0,};
			ua_mnem(cref,op_buffer,sizeof(op_buffer));
			if(cmd.itype==NN_call || cmd.itype==NN_callfi || cmd.itype==NN_callni)
			{
				is_function=true;
				break;
			}
		}
		cref=get_next_cref_to(address,cref);
	}

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
				char cref_function_name[1024];
				get_func_name(cref,cref_function_name,sizeof(cref_function_name));
				msg("Adding Location %s(%x) To Function Member Of %s(%x:%x)\n",function_name,address,cref_function_name,cref_func->startEA,cref);
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
			char op_buffer[40]={0,};
			ua_mnem(cref,op_buffer,sizeof(op_buffer));
			if(!(cmd.itype==NN_call || cmd.itype==NN_callfi || cmd.itype==NN_callni))
			{
				func_t *cref_func=get_func(cref);
				if(cref_func)
				{
					char cref_function_name[1024];
					get_func_name(cref,cref_function_name,sizeof(cref_function_name));
					msg("Adding Function %s(%x) To Function Member Of %s(%x:%x)\n",function_name,address,cref_function_name,cref_func->startEA,cref);
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
		for(int i=0;i<get_func_qty();i++)
		{
			func_t *f=getn_func(i);
			char function_name[100]={0,};
			get_func_name(f->startEA,function_name,sizeof(function_name));
			if(!IsValidFunctionStart(f->startEA))
			{
				connected_links_count+=ConnectBrokenFunctionChunk(f->startEA);
			}		
		}
	}while(connected_links_count>0);
}