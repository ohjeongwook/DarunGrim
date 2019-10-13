#pragma once
#include <windows.h>
#include <string>
#include <tchar.h>
#include "RegistryUtil.h"
#include "LogOperation.h"

static CRITICAL_SECTION LogFileCS;
static HANDLE hLogFile;
static LONG LogFileCsInitialized;

BOOL LogOperation::OpenLogFile( std::string &log_filename )
{
	EnterCriticalSection( &LogFileCS );
	// Create the new file to write the upper-case version to.
	if (hLogFile == INVALID_HANDLE_VALUE && log_filename.size()>0)
	{
		hLogFile = CreateFile((LPTSTR) log_filename.c_str(),// file name 
				GENERIC_READ | GENERIC_WRITE,// open r-w 
				FILE_SHARE_READ,
				NULL,				// default security 
				OPEN_ALWAYS,		// overwrite existing
				FILE_ATTRIBUTE_NORMAL,// normal file 
				NULL);				// no template 
		if( hLogFile == INVALID_HANDLE_VALUE )
		{ 
			printf("CreateFile failed for [%s] with error %u.\r\n", log_filename.c_str(), GetLastError());
			LeaveCriticalSection( &LogFileCS );
			return FALSE;
		}
		SetFilePointer(hLogFile,0,0,FILE_END);
	}
	LeaveCriticalSection( &LogFileCS );
	return TRUE;
}

void LogOperation::CloseLogFile( )
{
	EnterCriticalSection( &LogFileCS );
	if( hLogFile != INVALID_HANDLE_VALUE )
	{
		CloseHandle( hLogFile );
		hLogFile = INVALID_HANDLE_VALUE;
	}
	LeaveCriticalSection( &LogFileCS );
}

void LogOperation::_Log(const CHAR *log_message)
{
	std::string full_log_message;
	if( OutputType & LogToFile )
	{
		if( hLogFile != INVALID_HANDLE_VALUE ) 
		{
			EnterCriticalSection( &LogFileCS );
			DWORD bytes_written;

			SYSTEMTIME lt;
			GetLocalTime(&lt);
			char time_buffer[50];
			_snprintf(time_buffer, sizeof(time_buffer), "[%02d/%02d/%04d %02d:%02d:%02d] ",
				lt.wMonth,
				lt.wDay,
				lt.wYear,
				lt.wHour,
				lt.wMinute,
				lt.wSecond);

			full_log_message = time_buffer;
			full_log_message += " [";
			full_log_message += CategoryName.c_str();
			full_log_message += "] ";
			full_log_message += log_message;

			DWORD ret = WriteFile( hLogFile,
				full_log_message.c_str(),
				full_log_message.length(),
				&bytes_written,
				NULL); 
			if( !ret ) 
			{
				printf("WriteFile failed with error %u.\r\n",GetLastError());
			}
			LeaveCriticalSection( &LogFileCS );
		}
		else
		{
			printf("%s", log_message);
		}
	}

	if( (OutputType & LogToDbgview) || (OutputType & LogToIDAMessageBox) || (OutputType & LogToStdout) )
	{
		full_log_message = "[";
		full_log_message += CategoryName.c_str();
		full_log_message += "] ";
		full_log_message += log_message;
	}

	if( OutputType & LogToDbgview )
		OutputDebugStringA( full_log_message.c_str() );

	if( OutputType & LogToIDAMessageBox )
	{
#ifdef IDA_PLUGIN
		msg("%s", full_log_message.c_str() );
#endif
	}

	if( OutputType & LogToStdout )
		printf("%s", full_log_message.c_str() );
}

void LogOperation::_Log(const WCHAR *log_message)
{
	CHAR log_message_a[1024];
	_snprintf(log_message_a, sizeof(log_message_a)-1, "%ws", log_message );
	_Log( log_message_a );
}

LogOperation::LogOperation( int output_type ): OutputType(output_type), DebugLevel(5)
{
	if( !GetConsoleWindow() )
		OutputType = LogToDbgview;
}

LogOperation::LogOperation( const char *category_name ): OutputType(LogToFile)
{
	SetCategory( category_name );
}

void LogOperation::InitLog()
{
	InitializeCriticalSection( &LogFileCS );
	hLogFile = INVALID_HANDLE_VALUE;
	//InterlockedExchange( &LogFileCsInitialized, 1 );
}

void LogOperation::FiniLog()
{
	//if( InterlockedExchange( &LogFileCsInitialized, 0 ) == 1 )
	{
		//CloseLogFile();
		DeleteCriticalSection( &LogFileCS );
	}
}

void LogOperation::RetrieveLogInfoFromRegistry()
{
	std::string key_name = "HKEY_LOCAL_MACHINE\\Software\\";
	key_name += CompanyName;
	key_name += "\\";
	key_name += ProductName;
	key_name += "\\Logging\\";

	std::string category_key_name = key_name;
	category_key_name += CategoryName;

	char *type = GetRegValueString( category_key_name.c_str(), "Type" );
	if( type )
	{
		if( !_stricmp( type, "stdout" ) )
		{
			OutputType = LogToStdout;
		}
		else if( !_stricmp( type, "dbgview" ) )
		{
			OutputType = LogToDbgview;
		}
		else if( !_stricmp( type, "file" ) )
		{
			OutputType = LogToFile;
		}
#ifdef IDA_PLUGIN
		else if( !_stricmp( type, "ida" ) )
		{
			OutputType = LogToIDAMessageBox;
		}
#endif
		free( type );
	}

	if( OutputType == LogToFile && hLogFile == INVALID_HANDLE_VALUE )
	{
		char *log_filename_str = GetRegValueString( key_name.c_str(), "LogFileName" );
		if( log_filename_str )
		{
			std::string log_filename = log_filename_str;
			free( log_filename_str );

			char *image_filename;
			char image_full_filename[MAX_PATH+1];
			GetModuleFileNameA( NULL, image_full_filename, MAX_PATH );
			image_filename = image_full_filename;
			for( int i = strlen( image_full_filename ) - 1; i >=0 ; i-- )
			{
				if( image_full_filename[i] == '\\' )
				{
					image_filename = image_full_filename + i + 1;
					break;
				}
			}

			log_filename += "-";
			log_filename += image_filename;

			DWORD pid = GetCurrentProcessId();
			char pid_buffer[11];

			_snprintf( pid_buffer, sizeof(pid_buffer) -1, "%d", pid );
			log_filename += "-";
			log_filename += pid_buffer;

			log_filename += ".log";
			OpenLogFile( log_filename );
		}
	}

	GetRegValueInteger( key_name.c_str(), "Level", DebugLevel );
}

void LogOperation::SetCompanyName( const char *company_name )
{
	CompanyName = company_name;
}

void LogOperation::SetProductName( const char *product_name )
{
	ProductName = product_name;
}

void LogOperation::SetCategory( const char *category_name )
{
	CategoryName = category_name;
	DebugLevel = 0;
	OutputType = LogToDbgview;
	if( CategoryName == "IEAutomator" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "AgentMain" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "Agent" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "LogByLogServer" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "AgentC" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "ProcessWorker" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "ProcessWorkerInBHO" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "LogMessage" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "ApplicationServer" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "ProcessWorkerProcessor" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "HookOperation" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "ProcessOperation" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "ProtocolTransport" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "LocalCommunicator" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "SocketConnection" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "SocketOperation" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "WorkQueueManager" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "SandBoxRuleManager" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "Controller" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "AgentManager::WorkOnItem" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "AgentManager" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "AgentController" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "LogServer::LogServerThreadCallback" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}
	else if( CategoryName == "LogServer" )
	{
		DebugLevel = 0;
		OutputType = LogToDbgview;
	}

	RetrieveLogInfoFromRegistry();
}

LogOperation::~LogOperation()
{
}

void LogOperation::SetOutputType( int output_type )
{
	OutputType = output_type;
}

void LogOperation::SetDebugLevel( DWORD newDebugLevel )
{
	DebugLevel = newDebugLevel;
}

void LogOperation::SetLogFilename( const char *filename )
{
	LogFilename = filename;

	CloseLogFile();
	OpenLogFile( LogFilename );
}

void LogOperation::Log(DWORD debug_level, int type, const CHAR *format, ...)
{
	if (debug_level <= DebugLevel && EnabledLogTypes.find(type) != EnabledLogTypes.end())
	{
		va_list args;
		va_start(args,format);
		CHAR log_message[1024]={0,};
		_vsnprintf(log_message,sizeof(log_message)/sizeof(char),format,args);
		va_end(args);

		_Log(log_message);
	}
}

void LogOperation::Log( const CHAR *format, ... )
{
	va_list args;
	va_start(args,format);
	CHAR log_message[1024]={0,};
	_vsnprintf(log_message,sizeof(log_message)/sizeof(char),format,args);
	va_end(args);
	_Log(log_message);
}


void LogOperation::EnableLogType(int log_level)
{
	EnabledLogTypes.insert(log_level);
}

void LogOperation::Log(DWORD debug_level, int type, const WCHAR *format, ...)
{
	if (debug_level <= DebugLevel && EnabledLogTypes.find(type) != EnabledLogTypes.end())
	{
		va_list args;
		va_start(args,format);
		WCHAR log_message[1024]={0,};
		_vsnwprintf(log_message,sizeof(log_message)/sizeof(char),format,args);
		va_end(args);

		_Log(log_message);
	}
}

void LogOperation::Log( const WCHAR *format, ... )
{
	va_list args;
	va_start(args,format);
	WCHAR log_message[1024]={0,};
	_vsnwprintf(log_message,sizeof(log_message)/sizeof(char),format,args);
	va_end(args);
	_Log(log_message);
}

void LogOperation::DumpHex( TCHAR *Prefix, unsigned char *Buffer, int BufferLen )
{
	TCHAR LineBuffer[256];
	memset(LineBuffer,' ',50);
	LineBuffer[50]=0;
	int cursor=0;
	TCHAR ascii[17];
	int start_i=0;
	int i;
	ascii[16]=0;

	for(i=0;i<BufferLen;i++)
	{
		_tprintf( LineBuffer+(i%16)*3,"%0.2X ",Buffer[i]);
		if(isprint(Buffer[i]))
			ascii[i%16]=Buffer[i];
		else
			ascii[i%16]='.';

		if(i%16==15) 
		{
			_tprintf(LineBuffer+48,TEXT("  %s"),ascii);
			Log( TEXT("%s%.8x: %s\r\n"),Prefix,start_i,LineBuffer);
			start_i=i+1;
		}
	}

	if(i%16!=0)
	{
		memset(LineBuffer+(i%16)*3,' ',(16-(i%16))*3);
		ascii[i%16]=0;
		_tprintf( LineBuffer+48, TEXT("  %s"),ascii);
		Log(TEXT("%s%.8x: %s\r\n"),Prefix,start_i,LineBuffer);
	}
}

void LogOperation::DumpHex( DWORD MessageDebugLevel, TCHAR *Prefix, unsigned char *Buffer, int BufferLen )
{
	if(MessageDebugLevel < DebugLevel)
	{
		DumpHex( Prefix, Buffer, BufferLen );
	}
}
