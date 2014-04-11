//#include "stdafx.h"
#pragma warning(disable:4005)
#include <cfix.h>
#include "Implementation.h"

static void __stdcall FixtureSetup()
{
	CFIX_ASSERT( 0 != 1 );
}
static void __stdcall FixtureTeardown()
{
	CFIX_LOG( TEXT("Tearing down..."));
}

static void __stdcall Test()
{
	DWORD a = 1;
	DWORD b = 1;
	CFIX_ASSERT_EQUALS_DWORD( a, b );
	CFIX_ASSERT( a + b == 2 );

	//
	// Log a message -- printf-style formatting may be used.
	//
	CFIX_LOG( TEXT("a=%d, b=%d"), a, b );
}

CFIX_BEGIN_FIXTURE( MyFixture )
	CFIX_FIXTURE_ENTRY( Test )
	CFIX_FIXTURE_SETUP( FixtureSetup )
	CFIX_FIXTURE_TEARDOWN( FixtureTeardown )
CFIX_END_FIXTURE()
