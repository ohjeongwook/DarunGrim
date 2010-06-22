#include <winsock2.h>

#include "IDAClientManager.h"
#include "SocketOperation.h"
#include "DataBaseWriter.h"
#include "ProcessUtils.h"
#include "LogOperation.h"

extern LogOperation Logger;

#define DATA_BUFSIZE 4096
#define DEFAULT_IDA_PATH TEXT( "c:\\Program Files\\IDA\\idag.exe" )

IDAClientManager::IDAClientManager(): 
	EscapedOutputFilename( NULL ), 
	EscapedLogFilename( NULL ), 
	ListeningSocket( INVALID_SOCKET ), 
	TheSource( NULL ), 
	TheTarget( NULL ),
	IDACommandProcessorThreadId( -1 )
{
	IDAPath=_strdup( DEFAULT_IDA_PATH );
}

void IDAClientManager::SetDatabase( DBWrapper *OutputDB )
{
	m_OutputDB=OutputDB;
}

bool IDAClientManager::StartIDAListener( unsigned short port )
{	
	StopIDAListener();
	ListeningPort=port;
	if( ListeningPort>0 )
	{
		ListeningSocket = CreateListener( NULL, port );
		Logger.Log( 10, "%s: ListeningSocket=%d\n", __FUNCTION__, ListeningSocket );
		return TRUE;
	}
	return FALSE;
}

bool IDAClientManager::StopIDAListener()
{	
	if( ListeningSocket != INVALID_SOCKET )
	{
		closesocket( ListeningSocket );
		return TRUE;
	}
	return FALSE;
}

IDAClientManager::~IDAClientManager()
{
	StopIDAListener();

	if( IDAPath )
		free( IDAPath );
	if( EscapedOutputFilename )
		free( EscapedOutputFilename );
	if( EscapedLogFilename )
		free( EscapedLogFilename );

	if( TheSource )
		delete TheSource;

	if( TheTarget )
		delete TheTarget;
}

OneIDAClientManager *IDAClientManager::GetOneIDAClientManagerFromFile( char *DataFile )
{
	OneIDAClientManager *pOneIDAClientManager=new OneIDAClientManager( m_OutputDB );
	pOneIDAClientManager->Retrieve( DataFile );
	return pOneIDAClientManager;
}

BOOL IDAClientManager::AcceptIDAClient( OneIDAClientManager *pOneIDAClientManager, bool RetrieveData )
{
	SOCKET ClientSocket=accept( ListeningSocket, NULL, NULL );
	Logger.Log( 10, "%s: accepting=%d\n", __FUNCTION__, ClientSocket );
	if( ClientSocket==INVALID_SOCKET )
	{
		int error=WSAGetLastError();
		Logger.Log( 10, "Socket error=%d\n", error );
		return FALSE;
	}else
	{
		if( RetrieveData )
		{
			Logger.Log( 10, "%s: Calling RetrieveIDARawDataFromSocket\n", __FUNCTION__ );
			pOneIDAClientManager->RetrieveIDARawDataFromSocket( ClientSocket );
		}
		else
		{
			Logger.Log( 10, "%s: SetSocket\n", __FUNCTION__ );
			pOneIDAClientManager->SetSocket( ClientSocket );
		}
		return TRUE;
	}
	return FALSE;
}

DWORD IDAClientManager::SetMembers( OneIDAClientManager *OneIDAClientManagerTheSource, OneIDAClientManager *OneIDAClientManagerTheTarget, DiffMachine *pArgDiffMachine )
{
	TheSource=OneIDAClientManagerTheSource;
	TheTarget=OneIDAClientManagerTheTarget;
	pDiffMachine=pArgDiffMachine;
	return 1;
}

DWORD IDAClientManager::IDACommandProcessor()
{
	SOCKET SocketArray[WSA_MAXIMUM_WAIT_EVENTS];
	WSAEVENT EventArray[WSA_MAXIMUM_WAIT_EVENTS];
	WSANETWORKEVENTS NetworkEvents;
	DWORD EventTotal=0, index;

	SocketArray[0]=TheSource->GetSocket();
	SocketArray[1]=TheTarget->GetSocket();
	for( int i=0;i<2;i++ )
	{
		WSAEVENT NewEvent=WSACreateEvent();
		WSAEventSelect( SocketArray[i], NewEvent, FD_READ|FD_CLOSE );
		EventArray[EventTotal]=NewEvent;
		EventTotal++;
	}
	while( 1 )
	{
		index=WSAWaitForMultipleEvents( EventTotal, 
			EventArray, 
			FALSE, 
			WSA_INFINITE, 
			FALSE );

		if( index<0 )
			break;
			
		index=index-WSA_WAIT_EVENT_0;
		//-------------------------
		// Iterate through all events and enumerate
		// if the wait does not fail.
		for( DWORD i=index; i<EventTotal; i++ )
		{
			if( SocketArray[i]==WSA_INVALID_HANDLE )
				continue;

			index=WSAWaitForMultipleEvents( 1, 
				&EventArray[i], 
				TRUE, 
				1000, 
				FALSE );
			if ( ( index !=WSA_WAIT_FAILED ) && ( index !=WSA_WAIT_TIMEOUT ) )
			{
				if( WSAEnumNetworkEvents( SocketArray[i], EventArray[i], &NetworkEvents )==0 )
				{
					Logger.Log( 10, "Signal( %d - %d )\n", i, NetworkEvents.lNetworkEvents );
					if( NetworkEvents.lNetworkEvents==FD_READ )
					{
						char buffer[DATA_BUFSIZE]={0, };
						WSABUF DataBuf;
						DataBuf.len=DATA_BUFSIZE;
						DataBuf.buf=buffer;
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
						PBYTE data=RecvTLVData( SocketArray[i], &type, &length );
						if( data )
						{
							Logger.Log( 10, "%s: Type: %d Length: %d data:%x\n", __FUNCTION__, type, length, data );
							if( type==SHOW_MATCH_ADDR && length>=4 )
							{
								DWORD address=*( DWORD * )data;
								Logger.Log( 10, "%s: Showing address=%x\n", __FUNCTION__, address );
								//Get Matching Address
								DWORD MatchingAddress=pDiffMachine->GetMatchAddr( i, address );
								if( MatchingAddress!=0 )
								{
									//Show using JUMP_TO_ADDR
									if( i==0 )
									{
										TheTarget->ShowAddress( MatchingAddress );
									}else
									{
										TheSource->ShowAddress( MatchingAddress );
									}
								}
							}
						}						
					}else if( NetworkEvents.lNetworkEvents==FD_CLOSE )
					{
						closesocket( SocketArray[i] );
						WSACloseEvent( EventArray[i] );
						memcpy( SocketArray+i, SocketArray+i+1, EventTotal-i+1 );
						memcpy( EventArray+i, EventArray+i+1, EventTotal-i+1 );
						EventTotal--;
						break;
					}
				}
			}
		}
	}
	return 1;
}

DWORD WINAPI IDACommandProcessorThread( LPVOID lpParameter )
{
	IDAClientManager *pIDAClientManager=( IDAClientManager * )lpParameter;
	pIDAClientManager->IDACommandProcessor();
	return 1;
}

BOOL IDAClientManager::CreateIDACommandProcessorThread()
{
	if( IDACommandProcessorThreadId > 0 )
	{
		HANDLE hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, IDACommandProcessorThreadId );
		if( hThread )
		{
			CloseHandle( hThread );
		}
		else
		{
			IDACommandProcessorThreadId = -1;
		}
	}

	if( IDACommandProcessorThreadId == -1 )
	{
		CreateThread( NULL, 0, IDACommandProcessorThread, ( PVOID )this, 0, &IDACommandProcessorThreadId );
		return TRUE;
	}
	return FALSE;
}

void SendAddMatchAddrTLVData( FunctionMatchInfo &Data, PVOID Context )
{
	OneIDAClientManager *TheSource=( OneIDAClientManager * )Context;
	if( TheSource )
	{
		TheSource->SendTLVData( 
			ADD_MATCH_ADDR, 
			( PBYTE )&( Data ), 
			sizeof( Data ) );
	}
}

void SendUnidentifiedAddrTLVData( DWORD Data, PVOID Context )
{
	OneIDAClientManager *TheSource=( OneIDAClientManager * )Context;
	if( TheSource )
	{
		TheSource->SendTLVData( 
			ADD_UNINDENTIFIED_ADDR, 
			( PBYTE )&( Data ), 
			sizeof( Data ) );
	}
}

void IDAClientManager::ShowResultsOnIDA()
{
	pDiffMachine->ExecuteOnFunctionMatchInfoList( SendAddMatchAddrTLVData, ( PVOID )TheSource );
	pDiffMachine->ExecuteOnTheSourceUnidentifedBlockHash( SendUnidentifiedAddrTLVData, ( PVOID )TheSource );
	pDiffMachine->ExecuteOnTheTargetUnidentifedBlockHash( SendUnidentifiedAddrTLVData, ( PVOID )TheTarget );
#ifdef TODO
	for( iter=ReverseFunctionMatchInfoList.begin();iter!=ReverseFunctionMatchInfoList.end();iter++ )
	{
		TheTarget->SendTLVData( 
			ADD_MATCH_ADDR, 
			( PBYTE )&( *iter ), 
			sizeof( *iter ) );
	}
#endif
	TheSource->SendTLVData( 
		SHOW_DATA, 
		( PBYTE )"test", 
		4 );
	TheTarget->SendTLVData( 
		SHOW_DATA, 
		( PBYTE )"test", 
		4 );	
}

#define RUN_DARUNGRIM2_PLUGIN_STR "static main()\n\
{\n\
	Wait();\n\
	RunPlugin( \"DarunGrim2\", 1 );\n\
	SetLogFile( \"%s\" );\n\
	SaveAnalysisData( \"%s\", %d, %d );\n\
	Exit( 0 );\n\
}"

#define CONNECT_TO_DARUNGRIM2_STR "static main()\n\
{\n\
	Wait();\n\
	RunPlugin( \"DarunGrim2\", 1 );\n\
	SetLogFile( \"%s\" );\n\
	ConnectToDarunGrim2();\n\
	Exit( 0 );\n\
}"

void IDAClientManager::SetIDAPath( const char *ParamIDAPath )
{
	if( IDAPath )
		free( IDAPath );
	IDAPath=_strdup( ParamIDAPath );
}

void IDAClientManager::SetOutputFilename( char *OutputFilename )
{
	//Create IDC file
	EscapedOutputFilename=( char * )malloc( strlen( OutputFilename )*2+1 );

	if( EscapedOutputFilename )
	{
		DWORD i=0, j=0;
		for( ;i<strlen( OutputFilename );i++, j++ )
		{
			EscapedOutputFilename[j]=OutputFilename[i];
			if( OutputFilename[i]=='\\' )
			{
				j++;
				EscapedOutputFilename[j]='\\';
			}
		}
		EscapedOutputFilename[j]=NULL;
	}
}

void IDAClientManager::SetLogFilename( char *LogFilename )
{
	EscapedLogFilename=NULL;
	if( LogFilename )
	{
		EscapedLogFilename=( char * )malloc( strlen( LogFilename )*2+1 );
		if( EscapedLogFilename )
		{
			DWORD i=0, j=0;
			for( ;i<strlen( LogFilename );i++, j++ )
			{
				EscapedLogFilename[j]=LogFilename[i];
				if( LogFilename[i]=='\\' )
				{
					j++;
					EscapedLogFilename[j]='\\';
				}
			}
			EscapedLogFilename[j]=NULL;
		}
	}
}

void IDAClientManager::RunIDAToGenerateDB( char *ida_filename, DWORD StartAddress, DWORD EndAddress )
{
	char *idc_filename=WriteToTemporaryFile( RUN_DARUNGRIM2_PLUGIN_STR, 
		EscapedLogFilename?EscapedLogFilename:"", 
		EscapedOutputFilename?EscapedOutputFilename:"", 
		StartAddress, 
		EndAddress );

	if( idc_filename )
	{
		//Run IDA
		Logger.Log( 10, "Analyzing [%s]( %s )\n", ida_filename, idc_filename );
		Logger.Log( 10, "Executing \"%s\" -A -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename );
		Execute( TRUE, "\"%s\" -A -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename );
		free( idc_filename );
	}
}


void IDAClientManager::ConnectToDarunGrim2( char *ida_filename )
{
	char *idc_filename=WriteToTemporaryFile( CONNECT_TO_DARUNGRIM2_STR, EscapedLogFilename?EscapedLogFilename:"");

	if( idc_filename )
	{
		//Run IDA
		Logger.Log( 10, "Analyzing [%s]( %s )\n", ida_filename, idc_filename );
		Logger.Log( 10, "Executing \"%s\" -A -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename );
		Execute( TRUE, "\"%s\" -A -S\"%s\" \"%s\"", IDAPath, idc_filename, ida_filename );
		free( idc_filename );
	}
}