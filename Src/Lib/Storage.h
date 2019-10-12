#pragma once
#include <stdio.h>
#include "sqlite3.h"
#include "IDAAnalysisCommon.h"
#include <string>
using namespace std;

typedef unsigned char BYTE;
typedef unsigned char *PBYTE;
typedef unsigned long DWORD;

class Storage
{
private:
	sqlite3 *db;
	string m_DatabaseName;

public:
    Storage(const char *DatabaseName = NULL);
    ~Storage();
    int DatabaseWriterWrapper(BYTE Type, PBYTE Data, DWORD Length);

    void CreateTables();
    bool Open(char *DatabaseName);
    const char *GetDatabaseName();
    void CloseDatabase();
    bool CreateDatabase(const char *DatabaseName);
    int BeginTransaction();
    int EndTransaction();
    int GetLastInsertRowID();
    int ExecuteStatement(sqlite3_callback callback, void *context, char *format, ...);
    static int display_callback(void *NotUsed, int argc, char **argv, char **azColName);
    static int ReadRecordIntegerCallback(void *arg, int argc, char **argv, char **names);
    static int ReadRecordStringCallback(void *arg, int argc, char **argv, char **names);
};
