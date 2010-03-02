#pragma warning (disable: 4819)
#pragma warning (disable: 4996)
#pragma warning (disable : 4786)
#pragma once

#include <windows.h>
#include "IDAAnalysis.h"
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include <iostream>
#include <hash_set>

#include "sqlite3.h"


int ExecuteStatement(sqlite3 *db,char *format, ...);
sqlite3 *InitializeDatabase(int arg);
void DeInitializeDatabase(sqlite3 *db);
void SaveToDatabase(sqlite3 *db,AddrMapHash *addr_map_base,LocationInfo *p_first_location_info);

