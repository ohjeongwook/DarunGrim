#pragma once
#include <windows.h>
#include <string>
#include <unordered_set>

using namespace std;
using namespace stdext;

enum LogOutputTypes { LogToStdout = 0x1, LogToDbgview = 0x2, LogToFile = 0x4, LogToIDAMessageBox = 0x8 };

class LogOperation
{
private:
    DWORD DebugLevel;
    unordered_set<DWORD> EnabledLogTypes;
    DWORD OutputType;

    std::string CompanyName;
    std::string ProductName;
    std::string CategoryName;
    std::string LogFilename;

    BOOL OpenLogFile(std::string& log_filename);
    void CloseLogFile();
    void _Log(const CHAR *log_message);
    void _Log(const WCHAR *log_message);
    void RetrieveLogInfoFromRegistry();

public:
    LogOperation(int output_type = LogToDbgview);
    LogOperation(const char *category_name);
    static void InitLog();
    static void FiniLog();
    ~LogOperation();

    void SetCompanyName(const char *company_name);
    void SetProductName(const char *product_name);
    void EnableLogType(int log_level);
    void SetCategory(const char *category_name);
    void SetOutputType(int output_type);
    void SetDebugLevel(DWORD debug_level);
    void SetLogFilename(const char *filename);

    void Log(DWORD debug_level, int type, const CHAR *format, ...);
    void Log(DWORD debug_level, int type, const WCHAR *format, ...);
    void Log(const CHAR *format, ...);

    void Log(const WCHAR *format, ...);

    void DumpHex(TCHAR *Prefix, unsigned char *Buffer, int BufferLen);
    void DumpHex(DWORD MessageDebugLevel, TCHAR *Prefix, unsigned char *Buffer, int BufferLen);
};
