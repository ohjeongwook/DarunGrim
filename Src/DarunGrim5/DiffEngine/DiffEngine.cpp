// DiffEngine.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "DiffEngine.h"


// This is an example of an exported variable
DIFFENGINE_API int nDiffEngine=0;

// This is an example of an exported function.
DIFFENGINE_API int fnDiffEngine(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see DiffEngine.h for the class definition
CDiffEngine::CDiffEngine()
{
	return;
}
