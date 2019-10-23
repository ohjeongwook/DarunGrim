#pragma once
#include <windows.h>
#include "Configuration.h"
#include "DiffMachine.h"
#include "DisassemblyStorage.h"

#include <string>
using namespace std;
using namespace stdext;

#define DATA_BUFSIZE 4096
#define DEFAULT_IDA_PATH "c:\\Program Files\\IDA\\idag.exe"
#define DEFAULT_IDA64_PATH "c:\\Program Files\\IDA\\idag64.exe"

enum { SOURCE_CONTROLLER, TARGET_CONTROLLER };

class DarunGrim
{
private:
    IDASession* pSourceController;
    IDASession* pTargetController;

    DisassemblyStorage* pDisassemblyStorage;
    DiffMachine* pDiffMachine;
    bool OpenDatabase(char* storage_filename);
    string SourceFilename;
    string SourceIDBFilename;
    string TargetFilename;
    string TargetIDBFilename;
    bool IsLoadedSourceFile;
    bool IDAAutoMode;
    DumpAddressChecker aDumpAddress;

public:
    DarunGrim();
    ~DarunGrim();


    void AddSrcDumpAddress(va_t address)
    {
        aDumpAddress.AddSrcDumpAddress(address);
    }

    void AddTargetDumpAddress(va_t address)
    {
        aDumpAddress.AddTargetDumpAddress(address);
    }
    void EnableLogType(int type);

    DiffMachine* GetDiffMachine()
    {
        return pDiffMachine;
    }

    IDASession* GetSourceClientManager()
    {
        return pSourceController;
    }

    IDASession* GetTargetClientManager()
    {
        return pTargetController;
    }

    void JumpToAddress(va_t address, DWORD type)
    {
        if (type == SOURCE_CONTROLLER)
        {
            if (pSourceController)
            {
                pSourceController->JumpToAddress(address);
            }
        }
        else
        {
            if (pTargetController)
            {
                pTargetController->JumpToAddress(address);
            }
        }
    }

    void ShowReverseAddress(va_t address, DWORD type)
    {
        if (type == TARGET_CONTROLLER)
        {
            if (pSourceController)
            {
                pSourceController->JumpToAddress(address);
            }
        }
        else
        {
            if (pTargetController)
            {
                pTargetController->JumpToAddress(address);
            }
        }
    }

    char* GetSourceOrigFilename()
    {
        if (pSourceController)
        {
            char* filename = pSourceController->GetOriginalFilePath();
        }
        return NULL;
    }

    char* GetTargetOrigFilename()
    {
        if (pTargetController)
        {
            return pTargetController->GetOriginalFilePath();
        }
        return NULL;
    }

    list <BLOCK> GetSourceAddresses(va_t address)
    {
        return pSourceController->GetFunctionMemberBlocks(address);
    }

    list <BLOCK> GetTargetAddresses(va_t address)
    {
        return pTargetController->GetFunctionMemberBlocks(address);
    }

    void SetLogParameters(int ParamLogOutputType, int ParamDebugLevel, const char* LogFile = NULL);

    bool AcceptIDAClientsFromSocket(const char* storage_filename = NULL);

    bool Load(const char* storage_filename);

    bool PerformDiff();
    bool PerformDiff(const char* src_storage_filename, va_t source_address, const char* target_storage_filename, va_t target_address, const char* output_storage_filename);


    bool ShowOnIDA();

    const char* GetSourceFilename();
    const char* GetSourceIDBFilename();
    void SetSourceFilename(char* source_filename);
    const char* GetTargetFilename();
    const char* GetTargetIDBFilename();
    void SetTargetFilename(char* target_filename);
    bool LoadedSourceFile();
    void SetLoadedSourceFile(bool is_loaded);

    void JumpToAddresses(unsigned long source_address, unsigned long target_address);
    void ColorAddress(int type, unsigned long start_address, unsigned long end_address, unsigned long color);

private:
    DisassemblyStorage* m_disassemblyStorage;
    unsigned short ListeningPort;
    SOCKET ListeningSocket;
    IDASession* IDAControllers[2];

    char* IDAPath;
    char* IDA64Path;
    DWORD IDACommandProcessorThreadId;
    char IDALogFilename[MAX_PATH + 1];

    bool GenerateIDALogFilename();
    char* EscapeFilename(char* filename);
    char* LogFilename;
    PSLIST_HEADER pIDAClientListHead;
    vector<IDASession*> IDAControllerList;
    void UpdateIDAControllers();

    bool SetController(int type, const char* identity);
    string SourceIdentity;
    string TargetIdentity;
public:

    void SetDatabase(DisassemblyStorage* disassemblyStorage);
    unsigned short StartIDAListenerThread(unsigned short port);
    void ListIDAControllers();
    IDASession* FindIDAController(const char* identity);
    bool SetSourceController(const char* identity);
    bool SetTargetController(const char* identity);

    bool StartIDAListener(unsigned short port);
    bool StopIDAListener();

    IDASession* GetIDAControllerFromFile(char* DataFile);
    DWORD SetMembers(DiffMachine* pArgDiffMachine);
    DWORD IDACommandProcessor();
    BOOL CreateIDACommandProcessorThread();
    void SetIDAPath(const char* ParamIDAPath, bool is_64);
    void SetLogFilename(char* logfilename)
    {
        LogFilename = EscapeFilename(logfilename);
    }
    void GenerateSourceDGFFromIDA(char* output_filename, char* log_filename, bool is_64);
    void GenerateTargetDGFFromIDA(char* output_filename, char* log_filename, bool is_64);
    void GenerateDGFFromIDA(const char* ida_filename, unsigned long StartAddress, unsigned long EndAddress, char* output_filename, char* log_filename, bool is_64);
    void ConnectToDarunGrim(const char* ida_filename);
    void SetIDALogFilename(const char* ida_log_filename);
    const char* GetIDALogFilename();
    BOOL AcceptIDAClient(IDASession* p_ida_controller, bool retrieve_Data);
    void SetAutoMode(bool mode)
    {
        IDAAutoMode = mode;
    }
};
