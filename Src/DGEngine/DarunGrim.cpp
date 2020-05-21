#include <winsock2.h>
#include <Windows.h>

#include "Common.h"
#include "DarunGrim.h"
#include "LogOperation.h"

#include "SocketOperation.h"
#include "Storage.h"
#include "ProcessUtils.h"

#include "SQLiteStorage.h"

LogOperation Logger;

DarunGrim::DarunGrim() :
    m_disassemblyStorage(NULL),
    pSourceIDASession(NULL),
    pTargetIDASession(NULL),
    pIDASessions(NULL),
    LogFilename(NULL),
    IsLoadedSourceFile(false),
    ListeningSocket(INVALID_SOCKET),
    IDACommandProcessorThreadId(-1),
    IDAAutoMode(TRUE),
    pIDAClientListHead(NULL)
{
    LogOperation::InitLog();
    Logger.SetCategory("DarunGrim");
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);
    pIDASessions = new IDASessions();
    pIDASessions->SetDumpAddressChecker(&aDumpAddress);

    IDAPath = _strdup(DEFAULT_IDA_PATH);
    IDA64Path = _strdup(DEFAULT_IDA64_PATH);
    GenerateIDALogFilename();
}

DarunGrim::~DarunGrim()
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);
    if (m_disassemblyStorage)
    {
        m_disassemblyStorage->EndAnalysis();
        delete m_disassemblyStorage;
        m_disassemblyStorage = NULL;
    }

    if (pIDASessions)
    {
        delete pIDASessions;
        pIDASessions = NULL;
    }

    StopIDAListener();

    if (IDAPath)
        free(IDAPath);

    if (IDA64Path)
        free(IDA64Path);

    if (LogFilename)
        free(LogFilename);
}

void DarunGrim::EnableLogType(int type)
{
    Logger.EnableLogType(type);
}

void DarunGrim::SetLogParameters(int newLogOutputType, int newDebugLevel, const char *newLogFile)
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);
    Logger.Log(10, LOG_DARUNGRIM, "SetLogParameters: %d %d %s\n", newLogOutputType, newDebugLevel, newLogFile);

    Logger.SetOutputType(newLogOutputType);
    if (newLogFile)
        Logger.SetLogFilename(newLogFile);
    Logger.SetDebugLevel(newDebugLevel);
}

void DarunGrim::SetIDAPath(const char *ida_path, bool is_64)
{
    if (!is_64)
    {
        if (IDAPath)
            free(IDAPath);
        IDAPath = _strdup(ida_path);
    }
    else
    {
        if (IDA64Path)
            free(IDA64Path);
        IDA64Path = _strdup(ida_path);
    }
}

DWORD WINAPI ConnectToDarunGrimThread(LPVOID lpParameter)
{
    DarunGrim *pDarunGrim = (DarunGrim*)lpParameter;

    if (pDarunGrim)
    {
        const char *filename = NULL;
        if (!pDarunGrim->LoadedSourceFile())
        {
            filename = pDarunGrim->GetSourceIDBFilename();
            if (!filename)
            {
                filename = pDarunGrim->GetSourceFilename();
            }
        }
        else
        {
            filename = pDarunGrim->GetTargetIDBFilename();
            if (!filename)
            {
                filename = pDarunGrim->GetTargetFilename();
            }
        }

        if (filename)
            pDarunGrim->ConnectToDarunGrim(filename);
    }
    return 1;
}

const char *DarunGrim::GetSourceFilename()
{
    return SourceFilename.c_str();
}

const char *DarunGrim::GetSourceIDBFilename()
{
    if (GetFileAttributesA(SourceIDBFilename.c_str()) == INVALID_FILE_ATTRIBUTES)
        return NULL;
    return SourceIDBFilename.c_str();
}

void DarunGrim::SetSourceFilename(char *source_filename)
{
    SourceFilename = source_filename;
    SourceIDBFilename = SourceFilename;
    SourceIDBFilename = SourceIDBFilename.replace(SourceIDBFilename.length() - 4, SourceIDBFilename.length() - 1, ".idb");
}

const char *DarunGrim::GetTargetFilename()
{
    return TargetFilename.c_str();
}

const char *DarunGrim::GetTargetIDBFilename()
{
    if (GetFileAttributesA(TargetIDBFilename.c_str()) == INVALID_FILE_ATTRIBUTES)
        return NULL;
    return TargetIDBFilename.c_str();
}

void DarunGrim::SetTargetFilename(char *target_filename)
{
    TargetFilename = target_filename;
    TargetIDBFilename = TargetFilename;
    TargetIDBFilename = TargetIDBFilename.replace(TargetIDBFilename.length() - 4, TargetIDBFilename.length() - 1, ".idb");
}

bool DarunGrim::LoadedSourceFile()
{
    return IsLoadedSourceFile;
}

void DarunGrim::SetLoadedSourceFile(bool is_loaded)
{
    IsLoadedSourceFile = is_loaded;
}

bool DarunGrim::AcceptIDAClientsFromSocket(const char *storage_filename)
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);

    if (storage_filename)
    {
        if (m_disassemblyStorage)
            delete m_disassemblyStorage;

        m_disassemblyStorage = new SQLiteStorage(storage_filename);
    }

    if (m_disassemblyStorage)
    {
        SetDatabase(m_disassemblyStorage);
    }
    StartIDAListener(DARUNGRIM_PORT);

    pSourceIDASession = new IDASession(m_disassemblyStorage);
    pTargetIDASession = new IDASession(m_disassemblyStorage);

    //Create a thread that will call ConnectToDarunGrim one by one
    DWORD dwThreadId;
    CreateThread(NULL, 0, ConnectToDarunGrimThread, (PVOID)this, 0, &dwThreadId);
    AcceptIDAClient(pSourceIDASession, pIDASessions ? FALSE : m_disassemblyStorage ? TRUE : FALSE);
    SetLoadedSourceFile(TRUE);

    CreateThread(NULL, 0, ConnectToDarunGrimThread, (PVOID)this, 0, &dwThreadId);
    AcceptIDAClient(pTargetIDASession, pIDASessions ? FALSE : m_disassemblyStorage ? TRUE : FALSE);

    if (!pIDASessions)
    {
        PerformDiff();
    }

    CreateIDACommandProcessorThread();
    StopIDAListener();

    return TRUE;
}

bool DarunGrim::PerformDiff(const char *src_storage_filename, va_t source_address, const char *target_storage_filename, va_t target_address, const char *output_storage_filename)
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: (output storage: %s)\n", __FUNCTION__, output_storage_filename);

    Logger.Log(10, LOG_DARUNGRIM, "	source_address: %X\n", source_address);
    Logger.Log(10, LOG_DARUNGRIM, "	target_address: %X\n", target_address);

    pIDASessions->SetSource((char*)src_storage_filename, 1, source_address);
    pIDASessions->SetTarget((char*)target_storage_filename, 1, target_address);

    pIDASessions->SetLoadIDAController(true);
    pIDASessions->Load((char*)output_storage_filename);
    pSourceIDASession = pIDASessions->GetSourceIDASession();
    pTargetIDASession = pIDASessions->GetTargetIDASession();

    Logger.Log(10, LOG_DARUNGRIM, "Analyze\n");
    pIDASessions->Analyze();

    if (m_disassemblyStorage)
        delete m_disassemblyStorage;

    Logger.Log(10, LOG_DARUNGRIM, "Save\n");
    m_disassemblyStorage = new SQLiteStorage(output_storage_filename);
    SetDatabase(m_disassemblyStorage);

    pIDASessions->Save(*m_disassemblyStorage);

    return TRUE;
}

bool DarunGrim::OpenDatabase(char *storage_filename)
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);

    if (m_disassemblyStorage)
        delete m_disassemblyStorage;

    m_disassemblyStorage = new SQLiteStorage(storage_filename);
    return TRUE;
}

bool DarunGrim::Load(const char *storage_filename)
{
    m_disassemblyStorage = new SQLiteStorage(storage_filename);
    if (m_disassemblyStorage)
    {
        pIDASessions->SetRetrieveDataForAnalysis(TRUE);
        pIDASessions->Load(storage_filename);
        pSourceIDASession = pIDASessions->GetSourceIDASession();
        pTargetIDASession = pIDASessions->GetTargetIDASession();
    }
    return FALSE;
}

bool DarunGrim::PerformDiff()
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);
    int source_file_id = 1;
    int target_file_id = 2;

    if (m_disassemblyStorage)
    {
        pIDASessions->SetRetrieveDataForAnalysis(TRUE);
        pIDASessions->SetSource(m_disassemblyStorage, source_file_id);
        pIDASessions->SetSource(m_disassemblyStorage, target_file_id);
        pIDASessions->Load(m_disassemblyStorage);
        pSourceIDASession = pIDASessions->GetSourceIDASession();
        pTargetIDASession = pIDASessions->GetTargetIDASession();
    }
    else if (pSourceIDASession && pTargetIDASession)
    {
        pIDASessions->SetSource(pSourceIDASession);
        pIDASessions->SetTarget(pTargetIDASession);
    }

    if (pIDASessions)
    {
        pIDASessions->Analyze();
        pIDASessions->Save(*m_disassemblyStorage);
    }
    return TRUE;
}

bool DarunGrim::ShowOnIDA()
{
    Logger.Log(10, LOG_DARUNGRIM, "%s: entry\n", __FUNCTION__);
    IDACommandProcessor();
    return TRUE;
}

void DarunGrim::SetDatabase(Storage *OutputDB)
{
    m_disassemblyStorage = OutputDB;
}

typedef struct _IDA_LISTENER_PARAM_
{
    PSLIST_HEADER pListEntry;
    unsigned short port;
    SOCKET socket;
} IDA_LISTENER_PARAM;

typedef struct _IDA_CONTROLLER_
{
    SLIST_ENTRY ItemEntry;
    IDASession *pIDAController;
} IDA_CONTROLLER,  *PIDA_CONTROLLER;

DWORD WINAPI IDAListenerThread(LPVOID lpParameter)
{
    IDA_LISTENER_PARAM *param = (IDA_LISTENER_PARAM*)lpParameter;
    PSLIST_HEADER pListHead = param->pListEntry;
    SOCKET listen_s = param->socket;

    while (1)
    {
        SOCKET s = accept(listen_s, NULL, NULL);
        Logger.Log(10, LOG_DARUNGRIM, "%s: accepting=%d\n", __FUNCTION__, s);
        if (s == INVALID_SOCKET)
        {
            int error = WSAGetLastError();
            Logger.Log(10, LOG_DARUNGRIM, "Socket error=%d\n", error);
            return FALSE;
        }
        else
        {
            PIDA_CONTROLLER p_ida_controller_item = (PIDA_CONTROLLER)_aligned_malloc(sizeof(IDA_CONTROLLER), MEMORY_ALLOCATION_ALIGNMENT);
            if (p_ida_controller_item == NULL)
                return -1;
            Logger.Log(10, LOG_DARUNGRIM, "New connection: %d", s);
            p_ida_controller_item->pIDAController = new IDASession();
            p_ida_controller_item->pIDAController->SetSocket(s);
            p_ida_controller_item->pIDAController->RetrieveIdentity();

            Logger.Log(10, LOG_DARUNGRIM, "Identity: %s\n", p_ida_controller_item->pIDAController->GetIdentity());

            InterlockedPushEntrySList(pListHead, &(p_ida_controller_item->ItemEntry));
        }
    }
    return 0;
}

unsigned short DarunGrim::StartIDAListenerThread(unsigned short port)
{
    Logger.Log(10, LOG_DARUNGRIM, "StartIDAListenerThread on port: %d\n", port);
    DWORD dwThreadId;

    pIDAClientListHead = (PSLIST_HEADER)_aligned_malloc(sizeof(SLIST_HEADER), MEMORY_ALLOCATION_ALIGNMENT);

    if (pIDAClientListHead == NULL)
        return 0;

    InitializeSListHead(pIDAClientListHead);

    SOCKET s = CreateListener(NULL, port);
    Logger.Log(10, LOG_DARUNGRIM, "%s: listening socket: %d (port: %d)\n", __FUNCTION__, s, port);

    IDA_LISTENER_PARAM *param = new IDA_LISTENER_PARAM();
    param->pListEntry = pIDAClientListHead;
    param->port = port;
    param->socket = s;

    HANDLE thread = CreateThread(NULL, 0, IDAListenerThread, (PVOID)param, 0, &dwThreadId);

    return port;
}

void DarunGrim::UpdateIDAControllers()
{
    if (!pIDAClientListHead)
        return;

    while (1)
    {
        PSLIST_ENTRY pListEntry = InterlockedPopEntrySList(pIDAClientListHead);

        if (pListEntry == NULL)
            break;

        PIDA_CONTROLLER p_ida_controller_item = (PIDA_CONTROLLER)pListEntry;
        string identity = p_ida_controller_item->pIDAController->GetIdentity();

        Logger.Log(10, LOG_DARUNGRIM, "Identity: %s\n", identity.c_str());
        IDAControllerList.push_back(p_ida_controller_item->pIDAController);

        if (identity == SourceIdentity)
        {
            Logger.Log(10, LOG_DARUNGRIM, "Setting source controller: %s\n", identity.c_str());
            pSourceIDASession = p_ida_controller_item->pIDAController;
        }
        else if (identity == TargetIdentity)
        {
            Logger.Log(10, LOG_DARUNGRIM, "Setting target controller: %s\n", identity.c_str());
            pTargetIDASession = p_ida_controller_item->pIDAController;
        }
    }
}

void DarunGrim::ListIDAControllers()
{
    UpdateIDAControllers();
    //list clients from IDAControllerList
    for(IDASession *pIDASession: IDAControllerList)
    {
        Logger.Log(10, LOG_DARUNGRIM, "%s\n", pIDASession->GetIdentity());
    }
}

IDASession *DarunGrim::FindIDAController(const char *identity)
{
    UpdateIDAControllers();
    //list clients from IDAControllerList
    for (IDASession *pIDASession : IDAControllerList)
    {
        Logger.Log(10, LOG_DARUNGRIM, "%s\n", pIDASession->GetIdentity());

        if (pIDASession->GetIdentity() == identity)
            return pIDASession;
    }

    return NULL;
}

bool DarunGrim::SetController(int type, const char *identity)
{
    UpdateIDAControllers();
    //list clients from IDAControllerList
    for (IDASession *pIDASession : IDAControllerList)
    {
        Logger.Log(10, LOG_DARUNGRIM, "IDAController: %s\n", pIDASession->GetIdentity());

        if (pIDASession->GetIdentity() == identity)
        {
            Logger.Log(10, LOG_DARUNGRIM, "Setting source controller: %s\n", pIDASession->GetIdentity());
            if (type == SOURCE_CONTROLLER)
                pSourceIDASession = pIDASession;
            else if (type == TARGET_CONTROLLER)
                pTargetIDASession = pIDASession;

            return TRUE;
        }
    }

    return FALSE;
}

bool DarunGrim::SetSourceIDASession(const char *identity)
{
    SourceIdentity = identity;
    return SetController(SOURCE_CONTROLLER, identity);
}

bool DarunGrim::SetTargetIDASession(const char *identity)
{
    TargetIdentity = identity;
    return SetController(TARGET_CONTROLLER, identity);
}


void DarunGrim::JumpToAddresses(unsigned long source_address, unsigned long target_address)
{
    UpdateIDAControllers();

    if (pSourceIDASession)
        pSourceIDASession->JumpToAddress(source_address);

    if (pTargetIDASession)
        pTargetIDASession->JumpToAddress(target_address);
}

void DarunGrim::ColorAddress(int type, unsigned long start_address, unsigned long end_address, unsigned long color)
{
    UpdateIDAControllers();

    if (type == SOURCE_CONTROLLER)
    {
        if (pSourceIDASession)
            pSourceIDASession->ColorAddress(start_address, end_address, color);
    }
    else
    {
        if (pTargetIDASession)
            pTargetIDASession->ColorAddress(start_address, end_address, color);
    }
}

bool DarunGrim::StartIDAListener(unsigned short port)
{
    StopIDAListener();
    ListeningPort = port;
    if (ListeningPort > 0)
    {
        ListeningSocket = CreateListener(NULL, port);
        Logger.Log(10, LOG_DARUNGRIM, "%s: ListeningSocket=%d\n", __FUNCTION__, ListeningSocket);
        return TRUE;
    }
    return FALSE;
}

bool DarunGrim::StopIDAListener()
{
    if (ListeningSocket != INVALID_SOCKET)
    {
        closesocket(ListeningSocket);
        return TRUE;
    }
    return FALSE;
}

IDASession *DarunGrim::GetIDAControllerFromFile(char *DataFile)
{
    IDASession *p_ida_controller = new IDASession(m_disassemblyStorage);
    p_ida_controller->Retrieve(DataFile);
    return p_ida_controller;
}

BOOL DarunGrim::AcceptIDAClient(IDASession *p_ida_controller, bool retrieve_Data)
{
    SOCKET s = accept(ListeningSocket, NULL, NULL);
    Logger.Log(10, LOG_DARUNGRIM, "%s: accepting=%d\n", __FUNCTION__, s);
    if (s == INVALID_SOCKET)
    {
        int error = WSAGetLastError();
        Logger.Log(10, LOG_DARUNGRIM, "Socket error=%d\n", error);
        return FALSE;
    }
    else
    {
        if (retrieve_Data)
        {
            Logger.Log(10, LOG_DARUNGRIM, "%s: Calling LoadIDARawDataFromSocket\n", __FUNCTION__);
            p_ida_controller->LoadIDARawDataFromSocket(s);
        }
        else
        {
            Logger.Log(10, LOG_DARUNGRIM, "%s: SetSocket\n", __FUNCTION__);
            p_ida_controller->SetSocket(s);
        }
        return TRUE;
    }
    return FALSE;
}

DWORD DarunGrim::IDACommandProcessor()
{
    SOCKET SocketArray[WSA_MAXIMUM_WAIT_EVENTS];
    WSAEVENT EventArray[WSA_MAXIMUM_WAIT_EVENTS];
    WSANETWORKEVENTS NetworkEvents;
    DWORD EventTotal = 0, index;

    SocketArray[0] = pSourceIDASession->GetSocket();
    SocketArray[1] = pTargetIDASession->GetSocket();
    for (int i = 0; i < 2; i++)
    {
        WSAEVENT NewEvent = WSACreateEvent();
        WSAEventSelect(SocketArray[i], NewEvent, FD_READ | FD_CLOSE);
        EventArray[EventTotal] = NewEvent;
        EventTotal++;
    }
    while (1)
    {
        index = WSAWaitForMultipleEvents(EventTotal,
            EventArray,
            FALSE,
            WSA_INFINITE,
            FALSE);

        if (index < 0)
            break;

        index = index - WSA_WAIT_EVENT_0;
        //-------------------------
        // Iterate through all events and enumerate
        // if the wait does not fail.
        for (DWORD i = index; i < EventTotal; i++)
        {
            if (SocketArray[i] == WSA_INVALID_HANDLE)
                continue;

            index = WSAWaitForMultipleEvents(1,
                &EventArray[i],
                TRUE,
                1000,
                FALSE);
            if ((index != WSA_WAIT_FAILED) && (index != WSA_WAIT_TIMEOUT))
            {
                if (WSAEnumNetworkEvents(SocketArray[i], EventArray[i], &NetworkEvents) == 0)
                {
                    Logger.Log(10, LOG_DARUNGRIM, "Signal( %d - %d )\n", i, NetworkEvents.lNetworkEvents);
                    if (NetworkEvents.lNetworkEvents == FD_READ)
                    {
                        char buffer[DATA_BUFSIZE] = { 0, };
                        WSABUF DataBuf;
                        DataBuf.len = DATA_BUFSIZE;
                        DataBuf.buf = buffer;
                        /*
                        DWORD RecvBytes;
                        DWORD Flags=0;
                        if ( WSARecv( SocketArray[i], &DataBuf, 1, &RecvBytes, &Flags, NULL, NULL )==SOCKET_ERROR )
                        {
                        Logger.Log( 10, "Error occurred at WSARecv()\n" );
                        }else
                        {
                        Logger.Log( 10, "Read %d bytes\n", RecvBytes );
                        }*/
                        char type;
                        DWORD length;
                        PBYTE data = RecvTLVData(SocketArray[i], &type, &length);
                        if (data)
                        {
                            Logger.Log(10, LOG_DARUNGRIM, "%s: Type: %d Length: %d data:%X\n", __FUNCTION__, type, length, data);
                            if (type == SHOW_MATCH_ADDR && length >= 4)
                            {
                                va_t address = *(va_t*)data;
                                Logger.Log(10, LOG_DARUNGRIM, "%s: Showing address=%X\n", __FUNCTION__, address);
                                //Get Matching Address

                                DWORD MatchingAddress = 0;
                                if (pIDASessions)
                                {
                                    MatchingAddress = pIDASessions->GetMatchAddr(i, address);
                                }
                                if (MatchingAddress != 0)
                                {
                                    //Show using JUMP_TO_ADDR
                                    if (i == 0)
                                    {
                                        pTargetIDASession->JumpToAddress(MatchingAddress);
                                    }
                                    else
                                    {
                                        pSourceIDASession->JumpToAddress(MatchingAddress);
                                    }
                                }
                            }
                        }
                    }
                    else if (NetworkEvents.lNetworkEvents == FD_CLOSE)
                    {
                        closesocket(SocketArray[i]);
                        WSACloseEvent(EventArray[i]);
                        memcpy(SocketArray + i, SocketArray + i + 1, EventTotal - i + 1);
                        memcpy(EventArray + i, EventArray + i + 1, EventTotal - i + 1);
                        EventTotal--;
                        break;
                    }
                }
            }
        }
    }
    return 1;
}

DWORD WINAPI IDACommandProcessorThread(LPVOID lpParameter)
{
    DarunGrim *pDarunGrim = (DarunGrim*)lpParameter;
    pDarunGrim->IDACommandProcessor();
    return 1;
}

BOOL DarunGrim::CreateIDACommandProcessorThread()
{
    if (IDACommandProcessorThreadId > 0)
    {
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, IDACommandProcessorThreadId);
        if (hThread)
        {
            CloseHandle(hThread);
        }
        else
        {
            IDACommandProcessorThreadId = -1;
        }
    }

    if (IDACommandProcessorThreadId == -1)
    {
        CreateThread(NULL, 0, IDACommandProcessorThread, (PVOID)this, 0, &IDACommandProcessorThreadId);
        return TRUE;
    }
    return FALSE;
}

bool SendMatchedAddrTLVData(FunctionMatchInfo& Data, PVOID Context)
{
    IDASession *ClientManager = (IDASession*)Context;

    if (ClientManager)
    {
        return ClientManager->SendMatchedAddrTLVData(Data);
    }
    return false;
}

bool SendAddrTypeTLVData(int Type, va_t Start, va_t End, PVOID Context)
{
    IDASession *ClientManager = (IDASession*)Context;
    if (ClientManager)
    {
        return ClientManager->SendAddrTypeTLVData(Type, Start, End);
    }
    return false;
}


#define RUN_DARUNGRIM_PLUGIN_STR "static main()\n\
{\n\
    Wait();\n\
    RunPlugin( \"DarunGrimPlugin\", 1 );\n\
    SetLogFile( \"%s\" );\n\
    SaveAnalysisData( \"%s\", %d, %d );\n\
    Exit( 0 );\n\
}"

#define CONNECT_TO_DARUNGRIM_STR "static main()\n\
{\n\
    Wait();\n\
    RunPlugin( \"DarunGrimPlugin\", 1 );\n\
    SetLogFile( \"%s\" );\n\
    ConnectToDarunGrim();\n\
}"


char *DarunGrim::EscapeFilename(char *filename)
{
    //Create IDC file
    char *escaped_filename = (char*)malloc(strlen(filename)  *2 + 1);

    if (escaped_filename)
    {
        DWORD i = 0, j = 0;
        for (; i < strlen(filename); i++, j++)
        {
            escaped_filename[j] = filename[i];
            if (filename[i] == '\\')
            {
                j++;
                escaped_filename[j] = '\\';
            }
        }
        escaped_filename[j] = NULL;
    }

    return escaped_filename;
}

void DarunGrim::GenerateSourceDGFFromIDA(char *output_filename, char *log_filename, bool is_64)
{
    GenerateDGFFromIDA(SourceFilename.c_str(), 0, 0, output_filename, log_filename, is_64);
}

void DarunGrim::GenerateTargetDGFFromIDA(char *output_filename, char *log_filename, bool is_64)
{
    GenerateDGFFromIDA(TargetFilename.c_str(), 0, 0, output_filename, log_filename, is_64);
}

void DarunGrim::GenerateDGFFromIDA(const char *ida_filename, unsigned long StartAddress, unsigned long EndAddress, char *output_filename, char *log_filename, bool is_64)
{
    output_filename = EscapeFilename(output_filename);
    log_filename = EscapeFilename(log_filename);
    char *idc_filename = WriteToTemporaryFile(RUN_DARUNGRIM_PLUGIN_STR,
        log_filename ? log_filename : "",
        output_filename ? output_filename : "",
        StartAddress,
        EndAddress);
    free(output_filename);

    const char *options = IDAAutoMode ? "-A" : "";
    if (idc_filename)
    {
        if (LogFilename)
        {
            Logger.Log(10, LOG_DARUNGRIM, "Executing \"%s\" %s -L\"%s\" -S\"%s\" \"%s\"\n", is_64 ? IDA64Path : IDAPath, options, LogFilename, idc_filename, ida_filename);
            Execute(TRUE, "\"%s\" %s -L\"%s\" -S\"%s\" \"%s\"", is_64 ? IDA64Path : IDAPath, options, LogFilename, idc_filename, ida_filename);
        }
        else
        {
            Logger.Log(10, LOG_DARUNGRIM, "Executing \"%s\" %s -S\"%s\" \"%s\"\n", is_64 ? IDA64Path : IDAPath, options, idc_filename, ida_filename);
            Execute(TRUE, "\"%s\" %s -S\"%s\" \"%s\"", is_64 ? IDA64Path : IDAPath, options, idc_filename, ida_filename);
        }
        free(idc_filename);
    }
}


void DarunGrim::ConnectToDarunGrim(const char *ida_filename)
{
    char *idc_filename = WriteToTemporaryFile(CONNECT_TO_DARUNGRIM_STR, LogFilename ? LogFilename : "");

    if (idc_filename)
    {
        //Run IDA
        Logger.Log(10, LOG_DARUNGRIM, "Analyzing [%s]( %s )\n", ida_filename, idc_filename);
        Logger.Log(10, LOG_DARUNGRIM, "\"%s\" -S\"%s\" \"%s\"", IDAPath, LogFilename, idc_filename, ida_filename);

        if (IDALogFilename[0])
        {
            Execute(TRUE, "\"%s\" -L\"%s\" -S\"%s\" \"%s\"", IDAPath, IDALogFilename, idc_filename, ida_filename);
        }
        else
        {
            Execute(TRUE, "\"%s\" -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename);
        }
        free(idc_filename);
    }
}

bool DarunGrim::GenerateIDALogFilename()
{
    char temporary_path[MAX_PATH + 1];

    IDALogFilename[0] = NULL;
    // Get the temp path.
    DWORD ret_val = GetTempPathA(sizeof(temporary_path), temporary_path);
    if (ret_val <= sizeof(temporary_path) && (ret_val != 0))
    {
        ret_val = GetTempFileNameA(temporary_path,
            "IDALOG",
            0,
            IDALogFilename);
        if (ret_val != 0)
        {
            return true;
        }
    }
    return false;
}

void DarunGrim::SetIDALogFilename(const char *ida_log_filename)
{
    if (ida_log_filename)
    {
        strncpy(IDALogFilename, ida_log_filename, sizeof(IDALogFilename) - 1);
        IDALogFilename[sizeof(IDALogFilename) - 1] = NULL;
    }
    else
    {
        IDALogFilename[0] = NULL;
    }
}

const char *DarunGrim::GetIDALogFilename()
{
    return IDALogFilename;
}
