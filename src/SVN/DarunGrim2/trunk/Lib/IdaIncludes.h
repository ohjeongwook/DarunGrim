#pragma once
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

#define aux_rep				 0x0002
#define aux_repne			 0x0004

#define DEBUG_PRINT

bool IsNumber(char *data);
