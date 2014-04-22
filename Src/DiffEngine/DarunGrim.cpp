#include <winsock2.h>

#include "Common.h"
#include "DarunGrim.h"
#include "LogOperation.h"

#include "SocketOperation.h"
#include "DataBaseWriter.h"
#include "ProcessUtils.h"

LogOperation Logger;

DarunGrim::DarunGrim(): 
	pStorageDB(NULL),
	pSourceController(NULL),
	pTargetController(NULL),
	pDiffMachine(NULL),
	IsLoadedSourceFile( false ),
	EscapedOutputFilename(NULL),
	EscapedLogFilename(NULL),
	ListeningSocket(INVALID_SOCKET),
	IDACommandProcessorThreadId(-1)
{
	LogOperation::InitLog();
	Logger.SetCategory( "DarunGrim" );
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	pDiffMachine = new DiffMachine();
	IDAPath = _strdup(DEFAULT_IDA_PATH);
	GenerateIDALogFilename();
}

DarunGrim::~DarunGrim()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	if( pStorageDB )
	{
		pStorageDB->CloseDatabase();
		delete pStorageDB;
	}

	if( pDiffMachine )
		delete pDiffMachine;

	StopIDAListener();

	if (IDAPath)
		free(IDAPath);

	if (EscapedOutputFilename)
		free(EscapedOutputFilename);

	if (EscapedLogFilename)
		free(EscapedLogFilename);

}

void DarunGrim::SetLogParameters(int newLogOutputType, int newDebugLevel, const char *newLogFile)
{
	printf("SetLogParameters: %d %d %s\n", newLogOutputType, newDebugLevel, newLogFile);
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	Logger.SetOutputType(newLogOutputType);
	if (newLogFile)
		Logger.SetLogFilename(newLogFile);
	Logger.SetDebugLevel(newDebugLevel);
}

void DarunGrim::SetIDAPath(const char *ParamIDAPath)
{
	if (IDAPath)
		free(IDAPath);
	IDAPath = _strdup(ParamIDAPath);
}

bool DarunGrim::GenerateDB( 
	char *storage_filename, 
	char *log_filename, 
	char *ida_log_filename_for_source,
	char *ida_log_filename_for_target,
	unsigned long start_address_for_source, unsigned long end_address_for_source, 
	unsigned long start_address_for_target, unsigned long end_address_for_target )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	SetOutputFilename(storage_filename);
	SetLogFilename( log_filename );
	SetIDALogFilename( ida_log_filename_for_source );
	RunIDAToGenerateDB( SourceFilename.c_str(), start_address_for_source, end_address_for_source );
	SetIDALogFilename( ida_log_filename_for_target );
	RunIDAToGenerateDB( TargetFilename.c_str(), start_address_for_target, end_address_for_target );
	return OpenDatabase(storage_filename);
}

DWORD WINAPI ConnectToDarunGrimThread( LPVOID lpParameter )
{
	DarunGrim *pDarunGrim=( DarunGrim * )lpParameter;

	if( pDarunGrim )
	{
		const char *filename = NULL;
		if( !pDarunGrim->LoadedSourceFile() )
		{	
			filename = pDarunGrim->GetSourceIDBFilename();
			if( !filename )
			{
				filename = pDarunGrim->GetSourceFilename();
			}				
		}
		else
		{
			filename = pDarunGrim->GetTargetIDBFilename();
			if( !filename )
			{
				filename = pDarunGrim->GetTargetFilename();
			}
		}

		if( filename )
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
	if( GetFileAttributes( SourceIDBFilename.c_str() ) == INVALID_FILE_ATTRIBUTES )
		return NULL;
	return SourceIDBFilename.c_str();
}

void DarunGrim::SetSourceFilename( char *source_filename )
{
	SourceFilename = source_filename;
	SourceIDBFilename = SourceFilename;
	SourceIDBFilename = SourceIDBFilename.replace ( SourceIDBFilename.length() - 4 , SourceIDBFilename.length() - 1 , ".idb" );	
}

const char *DarunGrim::GetTargetFilename()
{
	return TargetFilename.c_str();
}

const char *DarunGrim::GetTargetIDBFilename()
{
	if( GetFileAttributes( TargetIDBFilename.c_str() ) == INVALID_FILE_ATTRIBUTES )
		return NULL;
	return TargetIDBFilename.c_str();
}

void DarunGrim::SetTargetFilename( char *target_filename )
{
	TargetFilename = target_filename;
	TargetIDBFilename = TargetFilename;
	TargetIDBFilename = TargetIDBFilename.replace ( TargetIDBFilename.length() - 4 , TargetIDBFilename.length() - 1 , ".idb" );	
}

bool DarunGrim::LoadedSourceFile()
{
	return IsLoadedSourceFile;
}

void DarunGrim::SetLoadedSourceFile( bool is_loaded )
{
	IsLoadedSourceFile = is_loaded;
}

bool DarunGrim::AcceptIDAClientsFromSocket( const char *storage_filename )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	if( storage_filename )
	{
		if( pStorageDB )
			delete pStorageDB;

		pStorageDB = new DBWrapper( (char *) storage_filename );
	}

	if( pStorageDB )
	{
		SetDatabase( pStorageDB );
	}
	StartIDAListener(DARUNGRIM_PORT);

	pSourceController=new IDAController( pStorageDB );
	pTargetController=new IDAController( pStorageDB );

	//Create a thread that will call ConnectToDarunGrim one by one
	DWORD dwThreadId;
	CreateThread( NULL, 0, ConnectToDarunGrimThread, ( PVOID )this, 0, &dwThreadId );
	AcceptIDAClient( pSourceController, pDiffMachine? FALSE:pStorageDB?TRUE:FALSE );
	SetLoadedSourceFile( TRUE );

	CreateThread( NULL, 0, ConnectToDarunGrimThread, ( PVOID )this, 0, &dwThreadId );
	AcceptIDAClient( pTargetController, pDiffMachine? FALSE:pStorageDB?TRUE:FALSE );

	if( !pDiffMachine )
	{
		Analyze();
	}
	CreateIDACommandProcessorThread();
	StopIDAListener();

	return TRUE;
}


int ReadFileInfo(void *arg, int argc, char **argv, char **names)
{
	for(int i=0;i<argc;i++)
	{
		Logger.Log(0,"%s: %s\n",names[i],argv[i]);
	}
	Logger.Log(0, "\n");
	return 0;
}


void DarunGrim::ListDiffDatabase(const char *storage_filename)
{
	DBWrapper *pStorageDB = new DBWrapper((char *)storage_filename);
	pStorageDB->ExecuteStatement(ReadFileInfo, NULL, "SELECT id,OriginalFilePath,ComputerName,UserName,CompanyName,FileVersion,FileDescription,InternalName,ProductName,ModifiedTime,MD5Sum From FileInfo");
}

bool DarunGrim::DiffDatabaseFiles(const char *src_storage_filename, DWORD source_address, const char *target_storage_filename, DWORD target_address, const char *output_storage_filename)
{
	Logger.Log(10, "%s: entry (%s)\n", __FUNCTION__, output_storage_filename);

	pDiffMachine->SetSource((char *)src_storage_filename, 1, source_address);
	pDiffMachine->SetTarget((char *)target_storage_filename, 1, target_address);
	pDiffMachine->SetLoadIDAController(true);
	pDiffMachine->Load((char *)output_storage_filename);
	pSourceController = pDiffMachine->GetSourceController();
	pTargetController = pDiffMachine->GetTargetController();

	Logger.Log(10, "Analyze\n");
	pDiffMachine->Analyze();

	if (pStorageDB)
		delete pStorageDB;

	Logger.Log(10, "Save\n");
	pStorageDB = new DBWrapper((char *)output_storage_filename);
	SetDatabase(pStorageDB);

	pDiffMachine->Save(*pStorageDB);

	return TRUE;
}

bool DarunGrim::OpenDatabase(char *storage_filename)
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	if( pStorageDB )
		delete pStorageDB;

	pStorageDB = new DBWrapper(storage_filename);

	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_START_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_END_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);
	return TRUE;
}

bool DarunGrim::Load( const char *storage_filename )
{
	pStorageDB = new DBWrapper( (char *) storage_filename );
	if( pStorageDB )
	{
		pDiffMachine->SetRetrieveDataForAnalysis(TRUE);
		pDiffMachine->Load(storage_filename);
		pSourceController = pDiffMachine->GetSourceController();
		pTargetController = pDiffMachine->GetTargetController();
	}
	return FALSE;
}

bool DarunGrim::Analyze()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	int source_file_id=1;
	int target_file_id=2;

	if( pStorageDB )
	{
		pDiffMachine->SetRetrieveDataForAnalysis(TRUE);
		pDiffMachine->SetSource(pStorageDB, source_file_id);
		pDiffMachine->SetSource(pStorageDB, target_file_id);
		pDiffMachine->Load(pStorageDB);
		pSourceController = pDiffMachine->GetSourceController();
		pTargetController = pDiffMachine->GetTargetController();
	}
	else if( pSourceController && pTargetController )
	{
		pDiffMachine->SetSource(pSourceController);
		pDiffMachine->SetTarget(pTargetController);
	}

	if( pDiffMachine )
	{
		pDiffMachine->Analyze();
		pDiffMachine->Save( *pStorageDB );
	}
	return TRUE;
}

bool DarunGrim::ShowOnIDA()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	IDACommandProcessor();
	return TRUE;
}

void DarunGrim::ShowAddresses( unsigned long source_address, unsigned long target_address )
{
	if( pSourceController )
		pSourceController->ShowAddress( source_address );

	if( pTargetController )
		pTargetController->ShowAddress( target_address );
}

void DarunGrim::ColorAddress( int index, unsigned long start_address, unsigned long end_address,unsigned long color )
{
	if( index == 0 )
	{
		if( pSourceController )
			pSourceController->ColorAddress( start_address, end_address, color );
	}
	else
	{
		if( pTargetController )
			pTargetController->ColorAddress( start_address, end_address, color );
	}
}

void DarunGrim::SetDatabase(DBWrapper *OutputDB)
{
	m_OutputDB = OutputDB;
}

bool DarunGrim::StartIDAListener(unsigned short port)
{
	StopIDAListener();
	ListeningPort = port;
	if (ListeningPort>0)
	{
		ListeningSocket = CreateListener(NULL, port);
		Logger.Log(10, "%s: ListeningSocket=%d\n", __FUNCTION__, ListeningSocket);
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

IDAController *DarunGrim::GetIDAControllerFromFile(char *DataFile)
{
	IDAController *pIDAController = new IDAController(m_OutputDB);
	pIDAController->Retrieve(DataFile);
	return pIDAController;
}

BOOL DarunGrim::AcceptIDAClient(IDAController *pIDAController, bool RetrieveData)
{
	SOCKET ClientSocket = accept(ListeningSocket, NULL, NULL);
	Logger.Log(10, "%s: accepting=%d\n", __FUNCTION__, ClientSocket);
	if (ClientSocket == INVALID_SOCKET)
	{
		int error = WSAGetLastError();
		Logger.Log(10, "Socket error=%d\n", error);
		return FALSE;
	}
	else
	{
		if (RetrieveData)
		{
			Logger.Log(10, "%s: Calling LoadIDARawDataFromSocket\n", __FUNCTION__);
			pIDAController->LoadIDARawDataFromSocket(ClientSocket);
		}
		else
		{
			Logger.Log(10, "%s: SetSocket\n", __FUNCTION__);
			pIDAController->SetSocket(ClientSocket);
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

	SocketArray[0] = pSourceController->GetSocket();
	SocketArray[1] = pTargetController->GetSocket();
	for (int i = 0; i<2; i++)
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

		if (index<0)
			break;

		index = index - WSA_WAIT_EVENT_0;
		//-------------------------
		// Iterate through all events and enumerate
		// if the wait does not fail.
		for (DWORD i = index; i<EventTotal; i++)
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
					Logger.Log(10, "Signal( %d - %d )\n", i, NetworkEvents.lNetworkEvents);
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
							Logger.Log(10, "%s: Type: %d Length: %d data:%x\n", __FUNCTION__, type, length, data);
							if (type == SHOW_MATCH_ADDR && length >= 4)
							{
								DWORD address = *(DWORD *)data;
								Logger.Log(10, "%s: Showing address=%x\n", __FUNCTION__, address);
								//Get Matching Address

								DWORD MatchingAddress = 0;
								if (pDiffMachine)
								{
									MatchingAddress = pDiffMachine->GetMatchAddr(i, address);
								}
								if (MatchingAddress != 0)
								{
									//Show using JUMP_TO_ADDR
									if (i == 0)
									{
										pTargetController->ShowAddress(MatchingAddress);
									}
									else
									{
										pSourceController->ShowAddress(MatchingAddress);
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
	DarunGrim *pDarunGrim = (DarunGrim *)lpParameter;
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

bool SendMatchedAddrTLVData(FunctionMatchInfo &Data, PVOID Context)
{
	IDAController *ClientManager = (IDAController *)Context;

	if (ClientManager)
	{
		return ClientManager->SendMatchedAddrTLVData(Data);
	}
	return false;
}

bool SendAddrTypeTLVData(int Type, DWORD Start, DWORD End, PVOID Context)
{
	IDAController *ClientManager = (IDAController *)Context;
	if (ClientManager)
	{
		return ClientManager->SendAddrTypeTLVData(Type, Start, End);
	}
	return false;
}


#define RUN_DARUNGRIM_PLUGIN_STR "static main()\n\
{\n\
	Wait();\n\
	RunPlugin( \"DarunGrim\", 1 );\n\
	SetLogFile( \"%s\" );\n\
	SaveAnalysisData( \"%s\", %d, %d );\n\
	Exit( 0 );\n\
}"

#define CONNECT_TO_DARUNGRIM_STR "static main()\n\
{\n\
	Wait();\n\
	RunPlugin( \"DarunGrim\", 1 );\n\
	SetLogFile( \"%s\" );\n\
	ConnectToDarunGrim();\n\
}"


void DarunGrim::SetOutputFilename(char *OutputFilename)
{
	//Create IDC file
	EscapedOutputFilename = (char *)malloc(strlen(OutputFilename) * 2 + 1);

	if (EscapedOutputFilename)
	{
		DWORD i = 0, j = 0;
		for (; i<strlen(OutputFilename); i++, j++)
		{
			EscapedOutputFilename[j] = OutputFilename[i];
			if (OutputFilename[i] == '\\')
			{
				j++;
				EscapedOutputFilename[j] = '\\';
			}
		}
		EscapedOutputFilename[j] = NULL;
	}
}

void DarunGrim::SetLogFilename(char *LogFilename)
{
	EscapedLogFilename = NULL;
	if (LogFilename)
	{
		EscapedLogFilename = (char *)malloc(strlen(LogFilename) * 2 + 1);
		if (EscapedLogFilename)
		{
			DWORD i = 0, j = 0;
			for (; i<strlen(LogFilename); i++, j++)
			{
				EscapedLogFilename[j] = LogFilename[i];
				if (LogFilename[i] == '\\')
				{
					j++;
					EscapedLogFilename[j] = '\\';
				}
			}
			EscapedLogFilename[j] = NULL;
		}
	}
}

void DarunGrim::RunIDAToGenerateDB(const char *ida_filename, unsigned long StartAddress, unsigned long EndAddress)
{
	char *idc_filename = WriteToTemporaryFile(RUN_DARUNGRIM_PLUGIN_STR,
		EscapedLogFilename ? EscapedLogFilename : "",
		EscapedOutputFilename ? EscapedOutputFilename : "",
		StartAddress,
		EndAddress);

	if (idc_filename)
	{
		//Run IDA
		Logger.Log(10, "Analyzing [%s]( %s )\n", ida_filename, idc_filename);
		if (IDALogFilename[0])
		{
			Logger.Log(10, "Executing \"%s\" -A -L\"%s\" -S\"%s\" \"%s\"", IDAPath, IDALogFilename, idc_filename, ida_filename);
			Execute(TRUE, "\"%s\" -A -L\"%s\" -S\"%s\" \"%s\"", IDAPath, IDALogFilename, idc_filename, ida_filename);
		}
		else
		{
			Logger.Log(10, "Executing \"%s\" -A -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename);
			Execute(TRUE, "\"%s\" -A -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename);
		}
		free(idc_filename);
	}
}


void DarunGrim::ConnectToDarunGrim(const char *ida_filename)
{
	char *idc_filename = WriteToTemporaryFile(CONNECT_TO_DARUNGRIM_STR, EscapedLogFilename ? EscapedLogFilename : "");

	if (idc_filename)
	{
		//Run IDA
		Logger.Log(10, "Analyzing [%s]( %s )\n", ida_filename, idc_filename);
		Logger.Log(10, "\"%s\" -S\"%s\" \"%s\"", IDAPath, EscapedLogFilename, idc_filename, ida_filename);

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
	DWORD ret_val = GetTempPath(sizeof(temporary_path), temporary_path);
	if (ret_val <= sizeof(temporary_path) && (ret_val != 0))
	{
		ret_val = GetTempFileName(temporary_path,
			TEXT("IDALOG"),
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
		strncpy(IDALogFilename, ida_log_filename, sizeof(IDALogFilename)-1);
		IDALogFilename[sizeof(IDALogFilename)-1] = NULL;
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
