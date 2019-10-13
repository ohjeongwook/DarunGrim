#include "Configuration.h"
#include "DiffMachine.h"
#include "DisassemblyStorage.h"
#include "XGetopt.h"
#include "ProcessUtils.h"
#include "dprintf.h"

#define strtoul10( X ) strtoul( X, NULL, 10 )
extern int DebugLevel;

void main( int argc, char *argv[] )
{
	int optind=1;

	int TheSourceFileID=1;
	int TheTargetFileID=2;

	char *OutputFilename=argv[optind];

	DiffMachine *pDiffMachine;	
    DisassemblyStorage disassemblyStorage( OutputFilename );
    disassemblyStorage.CreateTables();
	pDiffMachine=new DiffMachine();

	printf("Setting Analysis Target\n");
	pDiffMachine->SetTargetFunctions( 0x208a5d2a, 0x208a63b8 );

	printf("Retrieving Data\n");
	pDiffMachine->SetRetrieveDataForAnalysis(TRUE);
	pDiffMachine->SetSource(&disassemblyStorage, TheSourceFileID);
	pDiffMachine->SetSource(&disassemblyStorage, TheTargetFileID);
	pDiffMachine->Load(&disassemblyStorage);

	printf("Start Analysis\n");
	pDiffMachine->Analyze();
	//pDiffMachine->TestAnalysis();

	printf("Save the Results\n");
	pDiffMachine->Save( disassemblyStorage );
	
	disassemblyStorage.CloseDatabase();
}
