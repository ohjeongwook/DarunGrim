#pragma once
#pragma warning (disable : 4819)

#ifndef IDA_HEADER_INCLUDED
#define IDA_HEADER_INCLUDED
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <xref.hpp>
#include <intel.hpp>
#include <struct.hpp>
#endif

char *get_optype_str(optype_t optype);
int get_current_operand_pos();
void DumpOptInfo(op_t opt,char *prefix);
void DumpCurrentOptInfo(ea_t address,int i);
