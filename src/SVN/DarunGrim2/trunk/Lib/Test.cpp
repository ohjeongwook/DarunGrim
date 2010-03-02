//#include "stdafx.h"
#pragma warning(disable:4005)
#include <cfix.h>
#include "XGetopt.h"
#include <windows.h>
#include <tchar.h>

static void __stdcall FixtureSetup()
{
}
static void __stdcall FixtureTeardown()
{
}

static void __stdcall Test()
{
	int argc=4;
#define OPTION_FOR_B TEXT("option for b")
#define NEXT_ARG TEXT("Test")
	TCHAR *argv[]={TEXT("Test.exe"),TEXT("-a"),TEXT("-b"),OPTION_FOR_B,NEXT_ARG};
	TCHAR *optstring=TEXT("ab:");
	int optind=0;
	TCHAR *optarg;
	int c;

	printf("Calling getopt\n");
	int i=0;
	while((c=getopt(argc,argv,optstring,&optind,&optarg))!=EOF)
	{
		_tprintf(TEXT("c=%c optarg=%s\n"),c,optarg?optarg:TEXT(""));
		if(i==0)
			CFIX_ASSERT( c == TEXT('a') && optarg==NULL );
		if(i==1)
			CFIX_ASSERT( c == TEXT('b') && !_tcscmp(optarg,OPTION_FOR_B) );
		i++;
	}
	CFIX_ASSERT( optind==4 && !_tcscmp(argv[optind],NEXT_ARG) );
}

CFIX_BEGIN_FIXTURE( MyFixture )
	CFIX_FIXTURE_ENTRY( Test )
	CFIX_FIXTURE_SETUP( FixtureSetup )
	CFIX_FIXTURE_TEARDOWN( FixtureTeardown )
CFIX_END_FIXTURE()
