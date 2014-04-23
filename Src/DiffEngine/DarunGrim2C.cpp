#include "Common.h"

#ifdef _DEBUG
#include <conio.h>
#include <ctype.h>
#endif

#include "Configuration.h"
#include "DiffMachine.h"
#include "DataBaseWriter.h"
#include "XGetopt.h"
#include "ProcessUtils.h"
#include "dprintf.h"
#include "DarunGrim.h"

#define strtoul10(X) strtoul(X,NULL,10)
extern int DebugLevel;

void main(int argc,char *argv[])
{
	bool CreateNewDBFromIDA=TRUE;
	TCHAR *optstring=TEXT("f:i:I:L:ld:s:t:y");
	int optind=0;
	TCHAR *optarg;
	int c;

	char *SourceFilename=NULL;
	char *TargetFilename=NULL;
	char *LogFilename=NULL;
	BOOL bListFiles=FALSE;
	char *IDAPath=NULL;
	BOOL UseIDASync=FALSE;

	DWORD SourceFunctionAddress=0;
	DWORD TargetFunctionAddress = 0;

	int SourceFileID;
	int TargetFileID;

	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );

	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDOUT);
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDOUT);

	while((c=getopt(argc,argv,optstring,&optind,&optarg))!=EOF)
	{
		switch(c)
		{
			case 'f':
				SourceFilename=optarg;
				TargetFilename=argv[optind];
				optind++;
				break;

			case 'i':
				SourceFileID=strtoul10(optarg);
				TargetFileID=strtoul10(argv[optind]);
				optind++;
				break;

			case 'd':
				DebugLevel=strtoul10(optarg);
				break;

			case 's':
				SourceFunctionAddress = strtoul(optarg, NULL, 16);
				printf("SourceFunctionAddress: %x\n", SourceFunctionAddress);
				break;

			case 't':
				TargetFunctionAddress = strtoul(optarg, NULL, 16);
				printf("TargetFunctionAddress: %x\n", TargetFunctionAddress);
				break;

			case 'I':
				IDAPath=optarg;
				break;

			case 'L':
				LogFilename=optarg;
				break;

			case 'l':
				bListFiles=TRUE;
				break;

			case 'y':
				UseIDASync=TRUE;
				break;
		}
	}

	if(argc<=optind)
	{
		printf("Usage: %s [-f <original filename> <patched filename>]|[-i <original file id> <patched file id>]|-l -L <Log Filename> [-y] <database filename>\r\n"
			   			   
							" - f <original filename> <patched filename>\r\n"
							"	Original filename and patched filename\r\n"
							"		Retrieve data from IDA using DarunGrim IDA plugin\r\n"

							"-i <original file id> <patched file id>\r\n"
							"	Original files ID in the database and patched files ID in the database\r\n"
							"		Retrieve data from database file created using DarunGrim IDA plugin\r\n"

							"-I IDA Program path.\r\n"

							//Debugging related parameters
							"-L Debug Log Filename\r\n"
							"-d <level> Debug Level\r\n"

							"-s <function address> Function address to analyze for the original binary\r\n"
							"-t <function address> Function address to analyze for the patched binary\r\n"
							
							"-y Use IDA synchorinzation mode\r\n"
							
							"-l: \r\n"
							"	List file informations in the <database filename>\r\n"
							
							"<database filename>\r\n"
							"	Database filename to use\r\n\r\n", argv[0]);
		return;
	}

	DarunGrim *pDarunGrim = new DarunGrim();

	if (IDAPath)
		pDarunGrim->SetIDAPath(IDAPath);

	//pDarunGrim->SetLogParameters(LogToStdout, 100, "");

	char *DiffDatabaseFilename=argv[optind];
	
	if (bListFiles)
	{
		pDarunGrim->ListDiffDatabase(DiffDatabaseFilename);
	}
	else if (SourceFilename && TargetFilename && DiffDatabaseFilename)
	{
		pDarunGrim->DiffDatabaseFiles(
			SourceFilename, SourceFunctionAddress,
			TargetFilename, TargetFunctionAddress,
			DiffDatabaseFilename);
	}
	else
	{
		pDarunGrim->AcceptIDAClientsFromSocket();
	}

	pDarunGrim->Analyze();


	if(UseIDASync)
	{
		pDarunGrim->ShowOnIDA();
	}

	_CrtDumpMemoryLeaks();
}
