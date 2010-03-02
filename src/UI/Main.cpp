#pragma warning(disable:4996)
#include "stdafx.h"

#include <atlframe.h>
#include <atlctrls.h>
#include <atldlgs.h>
#include <atlmisc.h>
#include <atlsplit.h>
#include <atlctrlx.h>

#include "MainFrame.h"
#include "SplashWnd.h"
CAppModule _Module;

int Run(LPTSTR lpstrCmdLine=NULL,int nCmdShow=SW_SHOWDEFAULT)
{
	char *Filename=NULL;

	int    argc;
	WCHAR  *wcCommandLine;
	LPWSTR *argw;
	
	wcCommandLine=GetCommandLineW();	
	argw=CommandLineToArgvW(wcCommandLine,&argc);

	if(argw && argc>1)
	{
		int BuffSize=WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,argw[1],-1,NULL,0,NULL,NULL);
		if(BuffSize>0)
		{
			Filename=(char *)GlobalAlloc(LPTR,BuffSize);
			if(Filename)
				WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,argw[1],BuffSize*sizeof(WCHAR),Filename,BuffSize,NULL,NULL);
		}
	}

	CMessageLoop theLoop;
	_Module.AddMessageLoop(&theLoop);
	CMainFrame wndMain;
	//size of window to create
	CRect rc=CRect(0,0,800,600);
	if(wndMain.CreateEx(NULL,rc) == NULL)
	{
		ATLTRACE(_T("Main window creation failed!\n"));
		return 0;
	}
	/////////////////////////////////////////////
	//center and show main window
	wndMain.CenterWindow();
	wndMain.ShowWindow(nCmdShow);
	new CSplashWnd(IDB_SPLASH,3000,wndMain.m_hWnd);
	if(Filename)
		wndMain.SetDatabaseFilename(Filename);
	int nRet=theLoop.Run();
	_Module.RemoveMessageLoop();
	return nRet;
}

int WINAPI _tWinMain(HINSTANCE hInstance,HINSTANCE,LPTSTR lpstrCmdLine,int nCmdShow)
{
	HRESULT hRes=::CoInitialize(NULL);
	ATLASSERT(SUCCEEDED(hRes));
	::DefWindowProc(NULL,0,0,0L);
	hRes=_Module.Init(NULL,hInstance);
	ATLASSERT(SUCCEEDED(hRes));
	int nRet=Run(lpstrCmdLine,nCmdShow);
	_Module.Term();
	::CoUninitialize();
	return nRet;
}
