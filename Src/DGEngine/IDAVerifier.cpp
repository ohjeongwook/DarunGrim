#pragma warning(disable:4819)

#include <ida.hpp>
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

#include "Log.h"
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

int ConnectFunctionChunks(ea_t address)
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

	LogMessage(0, __FUNCTION__, "ConnectFunctionChunks: %s %s\n", function_name.c_str(), is_function? "is function": "is not function" );

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

				LogMessage(0, __FUNCTION__, "%s: Adding Location %s(%X) To Function Member Of %s(%X:%X)\n",
					__FUNCTION__,
					function_name.c_str(),
					address, 
					cref_function_name.c_str(),
					cref_func->start_ea, 
					cref
				);

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
					LogMessage(0, __FUNCTION__, "%s: Adding Function %s(%X) To Function Member Of %s(%X:%X)\n",
						__FUNCTION__,
						function_name,address,
						cref_function_name.c_str(),
						cref_func->start_ea, cref
					);

					append_func_tail(cref_func,address,GetBlockEnd(address));
					connected_links_count++;
				}
			}
			cref=get_next_cref_to(address,cref);
		}
	}
	return connected_links_count;
}

void FixFunctionChunks()
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

				LogMessage(0, __FUNCTION__, "%s: Found invalid function: %s\n", __FUNCTION__, function_name.c_str());
				connected_links_count+=ConnectFunctionChunks(f->start_ea);
			}		
		}
	}while(connected_links_count>0);
}

void MakeCode(ea_t start_addr, ea_t end_addr)
{
	while (1) {
		bool converted = TRUE;
		LogMessage(1, __FUNCTION__, "MakeCode: %X - %X \n", start_addr, end_addr);

		del_items(start_addr, 0, end_addr - start_addr);
		for (ea_t addr = start_addr; addr <= end_addr; addr += get_item_size(addr))
		{
			create_insn(addr);
			if (!is_code(get_full_flags(addr)))
			{
				converted = FALSE;
				break;
			}
		}
		if (converted)
			break;
		end_addr += get_item_size(end_addr);
	}
}

ea_t exception_handler_addr = 0L;

void FixExceptionHandlers()
{
	qstring name;

	for (int n = 0; n < get_segm_qty(); n++)
	{
		segment_t* seg_p = getnseg(n);
		if (seg_p->type == SEG_XTRN)
		{
			asize_t current_item_size;
			ea_t current_addr;
			for (current_addr = seg_p->start_ea;
				current_addr < seg_p->end_ea;
				current_addr += current_item_size)
			{
				get_name(&name, current_addr);
				if (!stricmp(name.c_str(), "_except_handler3") || !stricmp(name.c_str(), "__imp__except_handler3"))
				{
					LogMessage(1, __FUNCTION__, "name=%s\n", name);
					//dref_to
					ea_t sub_exception_handler = get_first_dref_to(current_addr);
					while (sub_exception_handler != BADADDR)
					{
						exception_handler_addr = sub_exception_handler;
						get_name(&name, sub_exception_handler);
						LogMessage(1, __FUNCTION__, "name=%s\n", name.c_str());

						ea_t push_exception_handler = get_first_dref_to(sub_exception_handler);
						while (push_exception_handler != BADADDR)
						{
							LogMessage(1, __FUNCTION__, "push exception_handler: %X\n", push_exception_handler);
							ea_t push_handlers_structure = get_first_cref_to(push_exception_handler);

							while (push_handlers_structure != BADADDR)
							{
								LogMessage(1, __FUNCTION__, "push hanlders structure: %X\n", push_handlers_structure);
								ea_t handlers_structure_start = get_first_dref_from(push_handlers_structure);
								while (handlers_structure_start != BADADDR)
								{
									qstring handlers_structure_start_name;
									get_name(&handlers_structure_start_name, handlers_structure_start);
									ea_t handlers_structure = handlers_structure_start;
									while (1)
									{
										LogMessage(1, __FUNCTION__, "handlers_structure: %X\n", handlers_structure);
										qstring handlers_structure_name;
										get_name(&handlers_structure_name, handlers_structure);

										if ((handlers_structure_name[0] != NULL &&
											strcmp(handlers_structure_start_name.c_str(), handlers_structure_name.c_str())) ||
											is_code(get_full_flags(handlers_structure))
											)
										{
											LogMessage(1, __FUNCTION__, "breaking\n");
											break;
										}
										if ((handlers_structure - handlers_structure_start) % 4 == 0)
										{
											int pos = (handlers_structure - handlers_structure_start) / 4;
											if (pos % 3 == 1 || pos % 3 == 2)
											{
												LogMessage(1, __FUNCTION__, "Checking handlers_structure: %X\n", handlers_structure);

												ea_t exception_handler_routine = get_first_dref_from(handlers_structure);
												while (exception_handler_routine != BADADDR)
												{
													LogMessage(1, __FUNCTION__, "Checking exception_handler_routine: %X\n", exception_handler_routine);
													if (!is_code(get_full_flags(exception_handler_routine)))
													{
														LogMessage(1, __FUNCTION__, "Reanalyzing exception_handler_routine: %X\n", exception_handler_routine);
														ea_t end_pos = exception_handler_routine;
														while (1)
														{
															if (!is_code(get_full_flags(end_pos)))
																end_pos += get_item_size(end_pos);
															else
																break;
														}
														if (!is_code(exception_handler_routine))
														{
															LogMessage(1, __FUNCTION__, "routine 01: %X~%X\n", exception_handler_routine, end_pos);
															MakeCode(exception_handler_routine, end_pos);
														}
													}
													exception_handler_routine = get_next_dref_from(handlers_structure, exception_handler_routine);
												}
											}
										}
										LogMessage(1, __FUNCTION__, "checked handlers_structure: %X\n", handlers_structure);
										handlers_structure += get_item_size(handlers_structure);
									}
									handlers_structure_start = get_next_dref_from(push_handlers_structure, handlers_structure_start);
								}
								push_handlers_structure = get_next_cref_to(push_exception_handler, push_handlers_structure);
							}
							push_exception_handler = get_next_dref_to(sub_exception_handler, push_exception_handler);
						}

						sub_exception_handler = get_next_dref_to(current_addr, sub_exception_handler);
					}

				}
				current_item_size = get_item_size(current_addr);
			}
		}
	}
}
