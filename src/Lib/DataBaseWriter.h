#pragma once
#pragma warning (disable: 4819)
#pragma warning (disable: 4996)
#pragma warning (disable : 4786)
#pragma warning(disable:4200)
#pragma warning(disable:4800)
#pragma warning(disable:4018)
#pragma warning(disable:4244)
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "IDAAnalysisCommon.h"
#include "fileinfo.h"
#include "DBWrapper.h"

void CreateTables(DBWrapper &db);
int DatabaseWriterWrapper(DBWrapper *db,BYTE Type,PBYTE Data,DWORD Length);
