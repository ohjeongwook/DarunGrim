#include "IDAClientManager.h"
#include "Configuration.h"
#include "DiffMachine.h"
#include "DataBaseWriter.h"
#include "XGetopt.h"
#include "ProcessUtils.h"
#include "dprintf.h"

#define strtoul10( X ) strtoul( X, NULL, 10 )
int DebugLevel=0;

void main( int argc, char *argv[] )
{
	int optind=1;

	int TheSourceFileID=1;
	int TheTargetFileID=2;

	char *OutputFilename=argv[optind];

	DiffMachine *pDiffMachine;	
	DBWrapper OutputDB( OutputFilename );
	CreateTables( OutputDB );
	pDiffMachine=new DiffMachine();
	pDiffMachine->Retrieve( OutputDB, TRUE, TheSourceFileID, TheTargetFileID, 0x208a5d2a, 0x208a63b8 );
	pDiffMachine->DeleteMatchInfo( OutputDB, TheSourceFileID, TheTargetFileID, 0x208a5d2a, 0x208a63b8 );
	pDiffMachine->Analyze();
	pDiffMachine->Save( OutputDB );
	
	OutputDB.CloseDatabase();
}
