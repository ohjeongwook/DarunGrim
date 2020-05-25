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
    Binary *m_psourceBinary;
    Binary *m_ptargetBinary;

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

    Binary *GetSourceClientManager()
    {
        return m_psourceBinary;
    }

    Binary *GetTargetClientManager()
    {
        return m_ptargetBinary;
    }

    void JumpToAddress(va_t address, DWORD type)
    {
        if (type == SOURCE_CONTROLLER)
        {
            if (m_psourceBinary)
            {
                m_psourceBinary->JumpToAddress(address);
            }
        }
        else
        {
            if (m_ptargetBinary)
            {
                m_ptargetBinary->JumpToAddress(address);
            }
        }
    }

    void ShowReverseAddress(va_t address, DWORD type)
    {
        if (type == TARGET_CONTROLLER)
        {
            if (m_psourceBinary)
            {
                m_psourceBinary->JumpToAddress(address);
            }
        }
        else
        {
            if (m_ptargetBinary)
            {
                m_ptargetBinary->JumpToAddress(address);
            }
        }
    }

    string GetSourceOrigFilename()
    {
        if (m_psourceBinary)
        {
            return m_psourceBinary->GetOriginalFilePath();
        }
        return {};
    }

    string GetTargetOrigFilename()
    {
        if (m_ptargetBinary)
        {
            return m_ptargetBinary->GetOriginalFilePath();
        }
        return {};
    }

    list <AddressRange> GetSourceAddresses(va_t address)
    {
        return m_psourceBinary->GetFunctionBasicBlocks(address);
    }

    list <AddressRange> GetTargetAddresses(va_t address)
    {
        return m_ptargetBinary->GetFunctionBasicBlocks(address);
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
    Binary *IDAControllers[2];

    char *IDAPath;
    char *IDA64Path;
    DWORD IDACommandProcessorThreadId;
    char IDALogFilename[MAX_PATH + 1];

    bool GenerateIDALogFilename();
    char *EscapeFilename(char *filename);
    char *LogFilename;
    PSLIST_HEADER pIDAClientListHead;
    vector<Binary*> IDAControllerList;
    void UpdateIDAControllers();

    bool SetController(int type, const char *identity);
    string SourceIdentity;
    string TargetIdentity;
public:

    void SetDatabase(DisassemblyStorage *p_disassemblyStorage);
    void ListIDAControllers();
    Binary *FindIDAController(const char *identity);
    bool SetSourceBinary(const char *identity);
    bool SetTargetBinary(const char *identity);

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
    BOOL AcceptIDAClient(Binary *p_ida_controller, bool retrieve_Data);
    void SetAutoMode(bool mode)
    {
        IDAAutoMode = mode;
    }
};
