#pragma once
#include <windows.h>
#include "Configuration.h"
#include "DiffLogic.h"
#include "DisassemblyStorage.h"
#include "DiffStorage.h"

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
    Loader *m_psourceLoader;
    Loader *m_ptargetLoader;

    DisassemblyStorage *m_pdisassemblyStorage;
    DiffStorage* m_pdiffStorage;

    DiffLogic *pDiffLogic;
    bool OpenDatabase(char *storage_filename);
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

    DiffLogic *GetDiffMachine()
    {
        return pDiffLogic;
    }

    Loader *GetSourceClientManager()
    {
        return m_psourceLoader;
    }

    Loader *GetTargetClientManager()
    {
        return m_ptargetLoader;
    }

    void JumpToAddress(va_t address, DWORD type)
    {
        if (type == SOURCE_CONTROLLER)
        {
            if (m_psourceLoader)
            {
                m_psourceLoader->JumpToAddress(address);
            }
        }
        else
        {
            if (m_ptargetLoader)
            {
                m_ptargetLoader->JumpToAddress(address);
            }
        }
    }

    void ShowReverseAddress(va_t address, DWORD type)
    {
        if (type == TARGET_CONTROLLER)
        {
            if (m_psourceLoader)
            {
                m_psourceLoader->JumpToAddress(address);
            }
        }
        else
        {
            if (m_ptargetLoader)
            {
                m_ptargetLoader->JumpToAddress(address);
            }
        }
    }

    char *GetSourceOrigFilename()
    {
        if (m_psourceLoader)
        {
            char *filename = m_psourceLoader->GetOriginalFilePath();
        }
        return NULL;
    }

    char *GetTargetOrigFilename()
    {
        if (m_ptargetLoader)
        {
            return m_ptargetLoader->GetOriginalFilePath();
        }
        return NULL;
    }

    list <BLOCK> GetSourceAddresses(va_t address)
    {
        return m_psourceLoader->GetFunctionMemberBlocks(address);
    }

    list <BLOCK> GetTargetAddresses(va_t address)
    {
        return m_ptargetLoader->GetFunctionMemberBlocks(address);
    }

    void SetLogParameters(int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL);

    bool Load(const char *storage_filename);

    bool PerformDiff();
    bool PerformDiff(const char *src_storage_filename, va_t source_address, const char *target_storage_filename, va_t target_address, const char *output_storage_filename);


    bool ShowOnIDA();

    const char *GetSourceFilename();
    const char *GetSourceIDBFilename();
    void SetSourceFilename(char *source_filename);
    const char *GetTargetFilename();
    const char *GetTargetIDBFilename();
    void SetTargetFilename(char *target_filename);
    bool LoadedSourceFile();
    void SetLoadedSourceFile(bool is_loaded);

    void JumpToAddresses(unsigned long source_address, unsigned long target_address);
    void ColorAddress(int type, unsigned long start_address, unsigned long end_address, unsigned long color);

private:
    DisassemblyStorage *m_storage;
    unsigned short ListeningPort;
    SOCKET ListeningSocket;
    Loader *IDAControllers[2];

    char *IDAPath;
    char *IDA64Path;
    DWORD IDACommandProcessorThreadId;
    char IDALogFilename[MAX_PATH + 1];

    bool GenerateIDALogFilename();
    char *EscapeFilename(char *filename);
    char *LogFilename;
    PSLIST_HEADER pIDAClientListHead;
    vector<Loader*> IDAControllerList;
    void UpdateIDAControllers();

    bool SetController(int type, const char *identity);
    string SourceIdentity;
    string TargetIdentity;
public:

    void SetDatabase(DisassemblyStorage *p_disassemblyStorage);
    void ListIDAControllers();
    Loader *FindIDAController(const char *identity);
    bool SetSourceLoader(const char *identity);
    bool SetTargetLoader(const char *identity);

    DWORD SetMembers(DiffLogic *pArgDiffMachine);
    DWORD IDACommandProcessor();
    BOOL CreateIDACommandProcessorThread();
    void SetIDAPath(const char *ParamIDAPath, bool is_64);
    void SetLogFilename(char *logfilename)
    {
        LogFilename = EscapeFilename(logfilename);
    }
    void GenerateSourceDGFFromIDA(char *output_filename, char *log_filename, bool is_64);
    void GenerateTargetDGFFromIDA(char *output_filename, char *log_filename, bool is_64);
    void GenerateDGFFromIDA(const char *ida_filename, unsigned long StartAddress, unsigned long EndAddress, char *output_filename, char *log_filename, bool is_64);
    void ConnectToDarunGrim(const char *ida_filename);
    void SetIDALogFilename(const char *ida_log_filename);
    const char *GetIDALogFilename();
    BOOL AcceptIDAClient(Loader *p_ida_controller, bool retrieve_Data);
    void SetAutoMode(bool mode)
    {
        IDAAutoMode = mode;
    }
};
