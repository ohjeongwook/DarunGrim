// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the DIFFENGINE_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// DIFFENGINE_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef DIFFENGINE_EXPORTS
#define DIFFENGINE_API __declspec(dllexport)
#else
#define DIFFENGINE_API __declspec(dllimport)
#endif

// This class is exported from the DiffEngine.dll
class DIFFENGINE_API CDiffEngine {
public:
	CDiffEngine(void);
	// TODO: add your methods here.
};

extern DIFFENGINE_API int nDiffEngine;

DIFFENGINE_API int fnDiffEngine(void);
