#if !defined(AFX_MAINFRM_H__BBA5DFCA_6C1A_11D6_B657_0048548B09C5__INCLUDED_)
#define AFX_MAINFRM_H__BBA5DFCA_6C1A_11D6_B657_0048548B09C5__INCLUDED_

#pragma once
#include "stdafx.h"
#include "CGraphVizWindow.h"

//DiffEngine
#include "Configuration.h"
#include "DiffMachine.h"
#include "DarunGrim.h"
//DiffEngine
#include "FlowGrapher.h"

#include "dprintf.h"

#include <hash_set>
#include <list>
#include <vector>
#include <hash_map>
#include <string>
#include <algorithm> 

using namespace std;
using namespace stdext;
#include "atlctrls.h"
#include "atlctrlw.h"

#include "DataBaseWriter.h"
#include "DBWrapper.h"

#include "ProcessUtils.h"

#include "resource.h"
#include "RC\resource.h"
#include "IDAConnectionDlg.h"
#include "SelectFilesDlg.h"
#include "LogViewerDlg.h"

#include "RegistryUtil.h"

#include "VirtualListViewCtrl.h"
#include "IDAConnectionDlg.h"
#include "OptionsDlg.h"


extern int GraphVizInterfaceProcessorDebugLevel;


int GraphViewSelectProxyCallback(DWORD address,DWORD ptr,DWORD index,int offset_x,int offset_y);
DWORD WINAPI PerformDiffThread(LPVOID pParam);
DWORD WINAPI OpenDatabaseThread(LPVOID pParam);

class DiffListSorter
{
private:
	int SortColumn = 6;
	bool Ascending = false;
	bool bDescendingSortInfos[10];

public:
	DiffListSorter()
	{
		memset(bDescendingSortInfos, 0, sizeof(bDescendingSortInfos));
	}

	void SortChange(int i)
	{
		bDescendingSortInfos[i] = bDescendingSortInfos[i] ? 0 : 1;
		SortColumn = i;
		Ascending = bDescendingSortInfos[i];
	}

	bool operator() (VirtualListDisplayItem *a, VirtualListDisplayItem *b)
	{
		if (Ascending)
		{
			return a->Items[SortColumn]<b->Items[SortColumn]; //ascending
		}
		else
		{
			return a->Items[SortColumn]>b->Items[SortColumn]; //descending
		}
	}
} ;

class MatchedBlocksSorter
{
private:
	int SortColumn = 0;
	bool Ascending = false;
	bool bDescendingSortInfos[10];

public:
	MatchedBlocksSorter()
	{
		memset(bDescendingSortInfos, 0, sizeof(bDescendingSortInfos));
	}

	void SortChange(int i)
	{
		bDescendingSortInfos[i] = bDescendingSortInfos[i] ? 0 : 1;
		SortColumn = i;
		Ascending = bDescendingSortInfos[i];
	}

	bool operator() (VirtualListDisplayItem *a, VirtualListDisplayItem *b)
	{
		if (Ascending)
		{
			return a->Items[SortColumn]<b->Items[SortColumn]; //ascending
		}
		else
		{
			return a->Items[SortColumn]>b->Items[SortColumn]; //descending
		}
	}
};

typedef struct
{
	DWORD original;
	DWORD patched;
} MatchAddressPair;

enum {STATE_NONE,STATE_DGF_CREATED,STATE_DGF_OPENED,STATE_ORIGINAL_ANALYZED,STATE_PATCHED_ACCEPTED,STATE_ANALYSIS_COMPLETED};

class CMainFrame : public CFrameWindowImpl<CMainFrame>, public CUpdateUI<CMainFrame>, public CMessageFilter
{
private:
	DarunGrim *pDarunGrim;
	DiffMachine *pDiffMachine;

	std::string m_IDAPath;
	char *m_LogFilename;

	string m_DiffFilename;
	string m_SourceFileName;
	string m_TargetFileName;
	CLogViwerDlg m_LogViewerDlg;

	CCommandBarCtrl m_CmdBar;
	float m_Zoom;
	bool m_RetrieveClientManagersDatabase;
	int AssociateSocketCount;
	int m_State;

public:
	DECLARE_FRAME_WND_CLASS(NULL,IDR_MAINFRAME)

	CSplitterWindow m_vSplit;
	CHorSplitterWindow m_hzSplit;
	CHorSplitterWindow m_hzmSplit;

	CPaneContainer m_lPane;
	CPaneContainer m_rPane;
	CPaneContainer m_bPane;
	CGraphVizWindow m_lGraphVizView;
	CGraphVizWindow m_rGraphVizView;
	CTabView m_TabView;

	CVirtualListViewCtrl<long> m_DiffListView;
	CVirtualListViewCtrl<long> m_MatchedBlocksView;

	BEGIN_MSG_MAP(CMainFrame)
		MESSAGE_HANDLER(WM_CREATE,OnCreate)
		COMMAND_ID_HANDLER(ID_PANE_CLOSE,OnPaneClose)
		COMMAND_ID_HANDLER(ID_APP_EXIT,OnFileExit)
		COMMAND_ID_HANDLER(ID_FILE_NEW,OnFileNew)
		COMMAND_ID_HANDLER(ID_FILE_OPEN,OnFileOpen)
		COMMAND_ID_HANDLER(ID_IDA_CONNECTIONS, OnIDAConnections)
		COMMAND_ID_HANDLER(ID_OPTIONS, OnOptions)
		COMMAND_ID_HANDLER(ID_SHOW_BREAKPOINTS, OnShowBreakpoints)
		COMMAND_ID_HANDLER(ID_VIEW_LOGVIEWER,OnViewLogViewer)	
		COMMAND_ID_HANDLER(ID_ZOOM_IN,OnZoomIn)
		COMMAND_ID_HANDLER(ID_ZOOM_OUT,OnZoomOut)
		COMMAND_ID_HANDLER(ID_ZOOM_ACTUAL,OnZoomActual)
		COMMAND_ID_HANDLER(ID_ACCEPT_COMPLETE, AssociateSocketComplete)
		COMMAND_ID_HANDLER(ID_SHOW_DIFF_RESULTS,ShowDiffResults)
		
		COMMAND_ID_HANDLER(ID_APP_ABOUT,OnAppAbout)
		NOTIFY_CODE_HANDLER(NM_DBLCLK, OnListViewDblClick)
		NOTIFY_CODE_HANDLER(LVN_COLUMNCLICK,OnListViewColumnClick)
		MESSAGE_HANDLER(WM_DROPFILES,OnDropFiles)
		CHAIN_MSG_MAP(CUpdateUI<CMainFrame>)
		CHAIN_MSG_MAP(CFrameWindowImpl<CMainFrame>)
		REFLECT_NOTIFICATIONS()
	END_MSG_MAP()

	virtual BOOL PreTranslateMessage(MSG* pMsg)
	{
		if (CFrameWindowImpl<CMainFrame>::PreTranslateMessage(pMsg))
			return TRUE;

		if (m_DiffListView.PreTranslateMessage(pMsg))
			return TRUE;

		if (m_MatchedBlocksView.PreTranslateMessage(pMsg))
			return TRUE;

		return FALSE;
	}

	virtual BOOL OnIdle()
	{
		UIUpdateToolBar();
		return FALSE;
	}

	BEGIN_UPDATE_UI_MAP(CMainFrame)
		UPDATE_ELEMENT(ID_VIEW_TOOLBAR, UPDUI_MENUPOPUP)
		UPDATE_ELEMENT(ID_VIEW_STATUS_BAR, UPDUI_MENUPOPUP)
	END_UPDATE_UI_MAP()

	void SetDatabaseFilename(char *Filename)
	{
		m_DiffFilename=Filename;
		OpenDatabase(m_DiffFilename.c_str());
	}

	CMainFrame()
	{
		pDiffMachine = NULL;
		m_RetrieveClientManagersDatabase = FALSE;
		pDiffListDisplayItemArray = NULL;
		pMatchedBlocksDisplayItemArray = NULL;
	}

	~CMainFrame()
	{
		m_LogViewerDlg.CloseDialog(0);
		
		if(m_LogFilename)
			free(m_LogFilename);

		if (pDarunGrim)
		{
			delete pDarunGrim;
		}
	}

	LRESULT OnCreate(UINT,WPARAM,LPARAM,BOOL&)
	{
		m_State=STATE_NONE;

		m_Zoom=1.0f;
		
		pDarunGrim = new DarunGrim();

		//Get ini file path
		std::string ConfFileName;
		char *InstallDir = GetRegValueString( "HKEY_LOCAL_MACHINE\\SOFTWARE\\DarunGrim4", "Install_Dir" );
		if( InstallDir )
		{
			ConfFileName = InstallDir;
			ConfFileName += "\\";
			free( InstallDir );
		}
		ConfFileName += "Conf.ini";
		//Get IDA Path
		
		char Buffer[1024]={0,};
		DWORD Ret=GetPrivateProfileString(
			"Paths",
			"IDA",
			NULL,
			Buffer,
			sizeof(Buffer),
			ConfFileName.c_str() );
		if(Ret>0)
		{
			m_IDAPath = Buffer;
		}

		//if Buffer is not there,
		if( GetFileAttributes( Buffer ) == INVALID_FILE_ATTRIBUTES )
		{
			//Detection through registry
			char *IDAPath = GetRegValueString( "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IDA Pro_is1", "Inno Setup: App Path" );
			if( IDAPath )
			{
				m_IDAPath = IDAPath;
				m_IDAPath += "\\idag.exe";
				free( IDAPath );
			}
		}
		dprintf("m_IDAPath=[%s]\n", m_IDAPath.c_str() );

		//Get Log File Path
		m_LogFilename=NULL;
		Ret=GetPrivateProfileString(
			"Paths",
			"Log",
			NULL,
			Buffer,
			sizeof(Buffer),
			ConfFileName.c_str() );
		if(Ret>0)
		{
			m_LogFilename=_strdup(Buffer);
		}

		// m_CmdBar is of type CCommandBarCtrl,defined in AtlCtrlw.h
		HWND hWndCmdBar=m_CmdBar.Create(m_hWnd,rcDefault,0,ATL_SIMPLE_CMDBAR_PANE_STYLE);

		// Let command bar replace the current menu
		m_CmdBar.AttachMenu(GetMenu());
		m_CmdBar.LoadImages(IDR_MAINFRAME);
		SetMenu(NULL);
		
		// First create a simple toolbar
		HWND hWndToolBar=CreateSimpleToolBarCtrl(m_hWnd,IDR_MAINFRAME,FALSE,ATL_SIMPLE_TOOLBAR_PANE_STYLE);
		
		// Set m_hWndToolBar member
		CreateSimpleReBar(ATL_SIMPLE_REBAR_NOBORDER_STYLE);
		
		// Add a band to the rebar represented by m_hWndToolBar
		AddSimpleReBarBand(hWndCmdBar);
		
		// Add another band to the m_hWndToolBar rebar
		AddSimpleReBarBand(hWndToolBar,NULL,TRUE);

		//Enable Dropping Files
		ModifyStyleEx(0,WS_EX_ACCEPTFILES);
		m_hWndClient=CreateClient();

		if(m_LogViewerDlg.Create(NULL) == NULL)
		{
			ATLTRACE(_T("Main dialog creation failed!\n"));
			return 0;
		}

		return 0;
	}

	HWND CreateClient()
	{
		// vertical splitter setup
		// client rect for vertical splitter
		CRect rcHorz;
		CRect rcVert;
		GetClientRect(&rcHorz);

		m_hzSplit.Create(m_hWnd,rcHorz,NULL,WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN);
		// set the horizontal splitter parameters
		m_hzSplit.m_cxyMin=35; // minimum size
		m_hzSplit.SetSplitterPos(rcHorz.Height()*5/8); // from top
		m_hzSplit.m_bFullDrag=false; // ghost bar enabled

		GetClientRect(&rcVert);
		// create the vertical splitter
		m_vSplit.Create(m_hzSplit.m_hWnd,rcVert,NULL,WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN);
		// set the vertical splitter parameters
		m_vSplit.m_cxyMin=35; // minimum size
		m_vSplit.SetSplitterPos(rcVert.Width()/2); // from left
		m_vSplit.m_bFullDrag=false; // ghost bar enabled

		m_hzSplit.SetSplitterPane(0,m_vSplit);
		// create the left container
		m_lPane.Create(m_vSplit.m_hWnd);
		m_lGraphVizView.Create(m_lPane.m_hWnd,rcDefault,NULL,WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN,WS_EX_CLIENTEDGE);
		m_lPane.SetClient(m_lGraphVizView);
		// add container to left pane (0) of vertical splitter
		m_vSplit.SetSplitterPane(0,m_lPane);
		// set the left pane title
		m_lPane.SetTitle("Original");
		m_lPane.SetPaneContainerExtendedStyle(PANECNT_NOCLOSEBUTTON);

		// create the left container
		m_rPane.Create(m_vSplit.m_hWnd);
		m_rGraphVizView.Create(m_rPane.m_hWnd,rcDefault,NULL,WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN,WS_EX_CLIENTEDGE);
		m_rPane.SetClient(m_rGraphVizView);
		// add container to left pane (0) of vertical splitter
		m_vSplit.SetSplitterPane(1,m_rPane);
		// set the left pane title
		m_rPane.SetTitle("Patched");
		m_rPane.SetPaneContainerExtendedStyle(PANECNT_NOCLOSEBUTTON);

		m_lGraphVizView.SetCallbackHandler(GraphViewSelectProxyCallback,(DWORD)this,0);
		m_rGraphVizView.SetCallbackHandler(GraphViewSelectProxyCallback,(DWORD)this,1);

		m_bPane.Create(m_hzSplit.m_hWnd);


		m_TabView.Create(m_bPane.m_hWnd,rcDefault,NULL,WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN,WS_EX_CLIENTEDGE);
		m_bPane.SetClient(m_TabView);

		m_DiffListView.Create(m_TabView,
			rcDefault,
			NULL,
			WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN|LVS_REPORT,
			WS_EX_CLIENTEDGE);

		if(m_DiffListView.IsWindow())
			m_TabView.AddPage(m_DiffListView.m_hWnd,"Functions",0,&m_DiffListView);

		m_DiffListView.SetExtendedListViewStyle(LVS_EX_INFOTIP|LVS_EX_FULLROWSELECT|LVS_EX_CHECKBOXES);
		m_DiffListView.AddColumn(_T("Original"),0);
		m_DiffListView.SetColumnWidth(0,230);
		m_DiffListView.AddColumn(_T("Unmatched"),1);
		m_DiffListView.SetColumnWidth(1,60);
		m_DiffListView.AddColumn(_T("Patched"),2);
		m_DiffListView.SetColumnWidth(2,230);
		m_DiffListView.AddColumn(_T("Unmatched"),3);
		m_DiffListView.SetColumnWidth(3,60);
		m_DiffListView.AddColumn(_T("Different"),4);
		m_DiffListView.SetColumnWidth(4,60);
		m_DiffListView.AddColumn(_T("Matched"),5);
		m_DiffListView.SetColumnWidth(5,60);
		m_DiffListView.AddColumn(_T("Match Rate"),6);
		m_DiffListView.SetColumnWidth(6,60);

		CRect TabViewRect;
		m_MatchedBlocksView.Create(m_TabView,
			rcDefault,
			NULL,
			WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|WS_CLIPCHILDREN|LVS_REPORT,
			WS_EX_CLIENTEDGE);
		if(m_MatchedBlocksView.IsWindow())
			m_TabView.AddPage(m_MatchedBlocksView.m_hWnd,"Blocks",0,&m_MatchedBlocksView);

		m_MatchedBlocksView.SetExtendedListViewStyle(LVS_EX_INFOTIP|LVS_EX_FULLROWSELECT|LVS_EX_CHECKBOXES);
		m_MatchedBlocksView.AddColumn(_T("Original"),0);
		m_MatchedBlocksView.SetColumnWidth(0,100);
		m_MatchedBlocksView.AddColumn(_T("Patched"),1);
		m_MatchedBlocksView.SetColumnWidth(1,100);
		m_MatchedBlocksView.AddColumn(_T("Match Rate"),2);
		m_MatchedBlocksView.SetColumnWidth(2,70);
		m_MatchedBlocksView.AddColumn(_T("Type"),3);
		m_MatchedBlocksView.SetColumnWidth(3,70);
		m_MatchedBlocksView.AddColumn(_T("Fingerprint(Original)"),4);
		m_MatchedBlocksView.SetColumnWidth(4,150);
		m_MatchedBlocksView.AddColumn(_T("Fingerprint(Patched)"),5);
		m_MatchedBlocksView.SetColumnWidth(5,150);
		m_MatchedBlocksView.AddColumn(_T("Parent(Original)"),6);
		m_MatchedBlocksView.SetColumnWidth(6,100);
		m_MatchedBlocksView.AddColumn(_T("Parent(Patched)"),7);
		m_MatchedBlocksView.SetColumnWidth(7,100);

		m_TabView.SetActivePage(0);
		// add container to left pane (0) of vertical splitter
		m_hzSplit.SetSplitterPane(1,m_bPane);
		// set the left pane title
		m_bPane.SetTitle("List Of Matches");
		m_bPane.SetPaneContainerExtendedStyle(PANECNT_NOCLOSEBUTTON);
		return m_hzSplit.m_hWnd;
	}


	void PrintToLogView(const TCHAR *format,...)
	{
		TCHAR statement_buffer[1024]={0,};

		va_list args;
		va_start(args,format);
		_vsntprintf(statement_buffer,sizeof(statement_buffer)/sizeof(TCHAR),format,args);
		va_end(args);
		m_LogViewerDlg.PostMessage(WM_COMMAND,ID_SHOW_LOG_MESSAGE,(LPARAM)_strdup(statement_buffer));
	}

	void DumpHex(char *Prefix,PBYTE buf,int buf_len)
	{
		char linebuf[256] ;
		memset(linebuf,' ',50) ;
		linebuf[50] = 0 ;
		int cursor = 0 ;
		char ascii[17] ;
		ascii[16] = 0 ;
		int i=0;
		if(buf_len==0)
			buf_len=strlen((const char *)buf);
		for(i=0; i<buf_len; i++)
		{
			sprintf(linebuf+(i%16)*3,"%0.2X ",buf[i]) ;
			if(isprint(buf[i]))
				ascii[i%16] = buf[i] ;
			else
				ascii[i%16] = '.' ;
	
			if(i % 16 == 15) 
			{
				sprintf(linebuf+48,"  %s",ascii) ;
				dprintf("%s: %s",Prefix,linebuf) ;
			}
		}
	
		if(i%16 != 0)
		{
			memset(linebuf+(i%16)*3,' ',(16-(i%16))*3) ;
			ascii[i%16] = 0 ;
			sprintf(linebuf+48,"  %s",ascii) ;
			dprintf("%s: %s",Prefix,linebuf) ;
		}
	}

	int GraphViewSelectCallback(DWORD address, DWORD index, int offset_x, int offset_y)
	{
		pDarunGrim->JumpToAddress(address, index);

		vector<MatchData *> match_data_list = pDiffMachine->GetMatchData(index, address);
		for (vector<MatchData *>::iterator it = match_data_list.begin();
			it != match_data_list.end();
			it++
			)
		{
			DWORD Address = (*it)->Addresses[index == 1 ? 0 : 1];

			pDarunGrim->JumpToAddress(Address, index);
			if (index == 0)
			{
				m_rGraphVizView.ShowNode(Address, offset_x, offset_y);
			}
			else
			{
				m_lGraphVizView.ShowNode(Address, offset_x, offset_y);
			}
			break;
		}

		pDiffMachine->CleanUpMatchDataList(match_data_list);
		return 0;
	}	

	void DrawOnGraphVizWindow(int index,CGraphVizWindow *pGraphVizWindow,IDAController *pIDAController,DWORD address)
	{
		FlowGrapher *p_flow_grapher=new FlowGrapher();
		if(address>0)
		{
			char name[100];
			_snprintf(name,sizeof(name),"%X",address);
			char *disasm_line=pIDAController->GetDisasmLines(address,0);
			
			char *font_color="black";
			char *fill_color="white";

			vector<MatchData *> match_data_list = pDiffMachine->GetMatchData(index, address);
			if (match_data_list.size()==0)
			{
				font_color="white";
				fill_color="crimson";
			}else
			{
				for (vector<MatchData *>::iterator it = match_data_list.begin();
						it != match_data_list.end();
						it++
				)
				{
					if ((*it)->MatchRate != 100)
					{
						font_color = "black";
						fill_color = "yellow";
						break;
					}
				}
			}

			pDiffMachine->CleanUpMatchDataList(match_data_list);

			p_flow_grapher->SetNodeShape(font_color, fill_color, "Verdana", "12");
			p_flow_grapher->AddNode(address, name, disasm_line ? disasm_line : "");
			if(disasm_line)
				free(disasm_line);
		}
		list <DWORD> address_list;
		list <DWORD>::iterator address_list_iter;
		hash_set <DWORD> checked_addresses;

		address_list.push_back(address);
		checked_addresses.insert(address);
		for(address_list_iter=address_list.begin();
			address_list_iter!=address_list.end();
			address_list_iter++
		)
		{
			int addresses_number;
			DWORD *p_addresses=pIDAController->GetMappedAddresses(*address_list_iter,CREF_FROM,&addresses_number);
			if(p_addresses && addresses_number>0)
			{
				for(int i=0;i<addresses_number;i++)
				{
					DWORD current_address=p_addresses[i];
					if(current_address)
					{
						if(checked_addresses.find(current_address)==checked_addresses.end())
						{
							address_list.push_back(current_address);
							checked_addresses.insert(current_address);
							char name[100];
							_snprintf(name,sizeof(name),"%X",current_address);
							char *disasm_line=pIDAController->GetDisasmLines(current_address,0);

							char *font_color="black";
							char *fill_color="white";

							vector<MatchData *> match_data_list = pDiffMachine->GetMatchData(index, current_address);
							if (match_data_list.size() == 0)
							{
								font_color = "white";
								fill_color = "red";
							}
							else
							{
								for (vector<MatchData *>::iterator it = match_data_list.begin();
									it != match_data_list.end();
									it++
									)
								{
									if ((*it)->MatchRate != 100)
									{
										font_color = "black";
										fill_color = "yellow";
										break;
									}
								}
								pDiffMachine->CleanUpMatchDataList(match_data_list);
							}							

							p_flow_grapher->SetNodeShape(font_color, fill_color, "Verdana", "12");
							p_flow_grapher->AddNode(current_address, name, disasm_line ? disasm_line : "");
							if(disasm_line)
								free(disasm_line);
						}
						p_flow_grapher->AddLink(*address_list_iter, current_address);
					}
				}
				free(p_addresses);
			}
		}

		p_flow_grapher->GenerateDrawingInfo();
		vector<DrawingInfo *> *drawing_object_list = p_flow_grapher->GetDrawingInfo();
		delete p_flow_grapher;
		pGraphVizWindow->SetDrawingObjectList(drawing_object_list);
	}

	typedef struct
	{
		CListViewCtrl* pList;
		int iColumn;
		bool bDescendingSort;
	} SortInfo;

	static int CALLBACK DiffListViewColumnCompareFunc(LPARAM lParam1,LPARAM lParam2,LPARAM lParamSort)
	{
		SortInfo *si=(SortInfo *)lParamSort;
		CString strItem1;
		si->pList->GetItemText(lParam1,si->iColumn,strItem1);
		CString strItem2;
		si->pList->GetItemText(lParam2,si->iColumn,strItem2);
		//return atoi(strItem1)-atoi(strItem2);
		return -1;
	}

	LRESULT OnPaneClose(WORD,WORD,HWND hWndCtl,BOOL&)
	{
		// hide the container whose Close button was clicked. Use 
		// DestroyWindow(hWndCtl) instead if you want to totally 
		// remove the container instead of just hiding it
		::ShowWindow(hWndCtl,SW_HIDE);
		// find the container's parent splitter
		HWND hWnd=::GetParent(hWndCtl);
		CSplitterWindow* pWnd;
		pWnd=(CSplitterWindow*)::GetWindowLong(hWnd,GWL_ID);
		// take the container that was Closed out of the splitter.
		// Use SetSplitterPane(nPane,NULL) if you want to stay in
		// multipane mode instead of changing to single pane mode
		int nCount=pWnd->m_nPanesCount;
		for(int nPane=0; nPane < nCount; nPane++)
		{
			if (hWndCtl==pWnd->m_hWndPane[nPane])
			{
				pWnd->SetSinglePaneMode(nCount - nPane - 1);
				break;
			}
		}

		return 0;
	}

	bool RetrieveClientManagersDatabase()
	{
		return m_RetrieveClientManagersDatabase;
	}

private:
	DiffListSorter m_DiffListSorter;
	vector<VirtualListDisplayItem *> *pDiffListDisplayItemArray;
	int m_DiffListCurrentID;

	MatchedBlocksSorter m_MatchedBlocksSorter;
	vector<VirtualListDisplayItem *> *pMatchedBlocksDisplayItemArray;
public:

	LRESULT OnListViewColumnClick(int idCtrl, LPNMHDR pnmh, BOOL& bHandled)
	{
		if (m_DiffListView.GetDlgCtrlID() == idCtrl)
		{
			LPNMLISTVIEW lpn = (LPNMLISTVIEW)pnmh;
			m_DiffListSorter.SortChange(lpn->iSubItem);
			DisplayDiffResults();
		}
		else if (m_MatchedBlocksView.GetDlgCtrlID() == idCtrl)
		{
			LPNMLISTVIEW lpn = (LPNMLISTVIEW)pnmh;
			m_MatchedBlocksSorter.SortChange(lpn->iSubItem);
			DisplayMatchedBlocks(false);
		}
		return 0;
	}

	void DisplayDiffResults()
	{
		int MatchCount=pDiffMachine->GetFunctionMatchInfoCount();

		PrintToLogView("Functions displayed: [%d]\r\n", MatchCount);

		if (pDiffListDisplayItemArray)
		{
			for (vector<VirtualListDisplayItem *>::iterator iter = pDiffListDisplayItemArray->begin();
				iter != pDiffListDisplayItemArray->end();
				iter++
				)
			{
				delete *iter;
			}
			delete pDiffListDisplayItemArray;
		}

		pDiffListDisplayItemArray = new vector<VirtualListDisplayItem *>();

		for(int i=0;i<MatchCount;i++)
		{
			FunctionMatchInfo match_info=pDiffMachine->GetFunctionMatchInfo(i);
			if (match_info.BlockType == FUNCTION_BLOCK && (OptionsDlg.ShowNonMatched || match_info.MatchRate < 100))
			{
				VirtualListDisplayItem *p_display_item = new VirtualListDisplayItem();

				p_display_item->id = i;

				char tmp[20];

				p_display_item->Items[0] = match_info.TheSourceFunctionName ? match_info.TheSourceFunctionName:"";

				_snprintf(tmp, sizeof(tmp), "%10d", match_info.NoneMatchCountForTheSource);
				p_display_item->Items[1] = tmp;

				p_display_item->Items[2] = match_info.TheTargetFunctionName ? match_info.TheTargetFunctionName:"";
				
				_snprintf(tmp, sizeof(tmp), "%10d", match_info.NoneMatchCountForTheTarget);
				p_display_item->Items[3] = tmp;

				_snprintf(tmp, sizeof(tmp), "%10d", match_info.MatchCountWithModificationForTheSource);
				p_display_item->Items[4] = tmp;
				
				_snprintf(tmp, sizeof(tmp), "%10d", match_info.MatchCountForTheSource);
				p_display_item->Items[5] = tmp;

				if (match_info.MatchRate == 0)
				{
					_snprintf(tmp, sizeof(tmp), "  0%%");
				}
				else
				{
					_snprintf(tmp, sizeof(tmp), "%3.d%%", (int)match_info.MatchRate);
				}
				p_display_item->Items[6] = tmp;

				pDiffListDisplayItemArray->push_back(p_display_item);
			}
		}
		
		sort(pDiffListDisplayItemArray->begin(), pDiffListDisplayItemArray->end(), m_DiffListSorter);

		m_DiffListView.DeleteAllItems();
		m_DiffListView.SetItemCount(pDiffListDisplayItemArray->size());
		m_DiffListView.SetData(pDiffListDisplayItemArray);
	}

	void DisplayMatchedBlocks(bool DisplayNewFunction = false)
	{
		m_MatchedBlocksView.DeleteAllItems();
		m_TabView.SetActivePage(1);

		IDAController *pSourceClientManager = pDiffMachine->GetSourceController();
		IDAController *pTargetClientManager = pDiffMachine->GetTargetController();

		FunctionMatchInfo match_info = pDiffMachine->GetFunctionMatchInfo(m_DiffListCurrentID);
		m_lPane.SetTitle(match_info.TheSourceFunctionName);
		m_rPane.SetTitle(match_info.TheTargetFunctionName);

		list <BLOCK> source_addresses = pDarunGrim->GetSourceAddresses(match_info.TheSourceAddress);
		list <BLOCK> target_addresses = pDarunGrim->GetTargetAddresses(match_info.TheTargetAddress);

		if (pMatchedBlocksDisplayItemArray)
		{
			for (vector<VirtualListDisplayItem *>::iterator iter = pMatchedBlocksDisplayItemArray->begin();
				iter != pMatchedBlocksDisplayItemArray->end();
				iter++
				)
			{
				delete *iter;
			}
			delete pMatchedBlocksDisplayItemArray;
		}

		pMatchedBlocksDisplayItemArray = new vector<VirtualListDisplayItem *>();

		hash_set <DWORD> matched_target_addresses;
		list <BLOCK>::iterator iter;
		for (iter = source_addresses.begin(); iter != source_addresses.end(); iter++)
		{
			if ((*iter).Start > 0)
			{
				VirtualListDisplayItem *p_display_item = new VirtualListDisplayItem();

				p_display_item->id = 0;

				char tmp[20];
				_snprintf(tmp, sizeof(tmp), "%X", (*iter).Start);

				p_display_item->Items[0] = tmp;

				//Fingerprint
				char *fingerprint = pSourceClientManager->GetFingerPrintStr((*iter).Start);
				if (fingerprint)
				{
					p_display_item->Items[4] = fingerprint;
					free(fingerprint);
				}

				MatchAddressPair *p_match_address_pair = new MatchAddressPair();
				p_match_address_pair->original = (*iter).Start;
				p_match_address_pair->patched = 0;

				vector<MatchData *> match_data_list = pDiffMachine->GetMatchData(0, (*iter).Start);
				if (match_data_list.size()>0)
				{
					for (vector<MatchData *>::iterator it = match_data_list.begin();
						it != match_data_list.end();
						it++
						)
					{
						matched_target_addresses.insert((*it)->Addresses[1]);
						_snprintf(tmp, sizeof(tmp), "%X", (*it)->Addresses[1]);
						p_display_item->Items[1] = tmp;

						_snprintf(tmp, sizeof(tmp), "%3.d%%", (*it)->MatchRate);
						p_display_item->Items[2] = tmp;

						if ((*it)->MatchRate != 100)
						{
							//Modified
							pSourceClientManager->SendAddrTypeTLVData(MODIFIED_ADDR, (*iter).Start, (*iter).End + 1);
						}

						//Type
						p_display_item->Items[3] = pDiffMachine->GetMatchTypeStr((*it)->Type);

						fingerprint = pTargetClientManager->GetFingerPrintStr((*it)->Addresses[1]);
						if (fingerprint)
						{
							p_display_item->Items[5] = fingerprint;
							free(fingerprint);
						}

						_snprintf(tmp, sizeof(tmp), "%X", (*it)->UnpatchedParentAddress);
						p_display_item->Items[6] = tmp;

						_snprintf(tmp, sizeof(tmp), "%X", (*it)->PatchedParentAddress);
						p_display_item->Items[7] = tmp;

						p_match_address_pair->patched = (*it)->Addresses[1];
					}

					pDiffMachine->CleanUpMatchDataList(match_data_list);
				}
				else
				{
					//Non-matched
					pSourceClientManager->SendAddrTypeTLVData(UNINDENTIFIED_ADDR, (*iter).Start, (*iter).End + 1);
				}

				p_display_item->data = p_match_address_pair;
				pMatchedBlocksDisplayItemArray->push_back(p_display_item);
			}
		}

		for (iter = target_addresses.begin(); iter != target_addresses.end(); iter++)
		{
			VirtualListDisplayItem *p_display_item = new VirtualListDisplayItem();

			p_display_item->id = 0;


			if (matched_target_addresses.find((*iter).Start) != matched_target_addresses.end())
			{
				vector<MatchData *> match_data_list = pDiffMachine->GetMatchData(1, (*iter).Start);

				for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
				{
					if ((*it)->MatchRate < 100)
					{
						pTargetClientManager->SendAddrTypeTLVData(MODIFIED_ADDR, (*iter).Start, (*iter).End + 1);
						break;
					}
				}

				pDiffMachine->CleanUpMatchDataList(match_data_list);
			}
			else if ((*iter).Start>0)
			{
				p_display_item->Items[0] = " ";

				char tmp[20];
				_snprintf(tmp, sizeof(tmp), "%X", (*iter).Start);

				p_display_item->Items[1] = tmp;

				MatchAddressPair *p_match_address_pair = new MatchAddressPair();
				p_match_address_pair->original = 0;
				p_match_address_pair->patched = (*iter).Start;
				
				vector<MatchData *> match_data_list = pDiffMachine->GetMatchData(1, (*iter).Start);

				if (match_data_list.size()>0)
				{
					for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
					{
						_snprintf(tmp, sizeof(tmp), "%X", (*it)->Addresses[0]);
						p_display_item->Items[0] = tmp;

						p_match_address_pair->original = (*it)->Addresses[0];
						break;
					}

					pDiffMachine->CleanUpMatchDataList(match_data_list);
				}
				else
				{
					//Non-matched
					pTargetClientManager->SendAddrTypeTLVData(UNINDENTIFIED_ADDR, (*iter).Start, (*iter).End + 1);
				}

				char *fingerprint = pTargetClientManager->GetFingerPrintStr((*iter).Start);
				if (fingerprint)
				{
					p_display_item->Items[5] = fingerprint;
					free(fingerprint);
				}

				p_display_item->data = p_match_address_pair;
				pMatchedBlocksDisplayItemArray->push_back(p_display_item);
			}
		}

		sort(pMatchedBlocksDisplayItemArray->begin(), pMatchedBlocksDisplayItemArray->end(), m_MatchedBlocksSorter);

		m_MatchedBlocksView.DeleteAllItems();
		m_MatchedBlocksView.SetItemCount(pMatchedBlocksDisplayItemArray->size());
		m_MatchedBlocksView.SetData(pMatchedBlocksDisplayItemArray);

		if (DisplayNewFunction)
		{
			bool draw_graphs = true;
			if (pMatchedBlocksDisplayItemArray->size() > 200)
			{
				if (::MessageBox(m_hWnd, "There are too many nodes to display, do you still want show graphs?", "Information", MB_YESNO) == IDNO)
				{
					draw_graphs = false;
				}
			}

			if (draw_graphs)
			{
				DrawOnGraphVizWindow(0, &m_lGraphVizView, pSourceClientManager, match_info.TheSourceAddress);
				DrawOnGraphVizWindow(1, &m_rGraphVizView, pTargetClientManager, match_info.TheTargetAddress);
			}
		}
	}

	LRESULT OnListViewDblClick(int idCtrl, LPNMHDR pnmh, BOOL& bHandled)
	{
		LPNMITEMACTIVATE pnmia = (LPNMITEMACTIVATE)pnmh;
		if (m_DiffListView.GetDlgCtrlID() == idCtrl)
		{
			m_DiffListCurrentID = m_DiffListView.GetID(pnmia->iItem);
			DisplayMatchedBlocks(true);
		}
		else if (m_MatchedBlocksView.GetDlgCtrlID() == idCtrl)
		{
			MatchAddressPair *p_match_address_pair = (MatchAddressPair *) m_MatchedBlocksView.GetData(pnmia->iItem);

			if (p_match_address_pair)
			{
				RECT rc;
				m_lGraphVizView.GetClientRect(&rc);
				m_lGraphVizView.ShowNode(p_match_address_pair->original, (rc.right - rc.left) / 2, (rc.bottom - rc.top) / 2);

				m_rGraphVizView.GetClientRect(&rc);
				m_rGraphVizView.ShowNode(p_match_address_pair->patched, (rc.right - rc.left) / 2, (rc.bottom - rc.top) / 2);

				pDarunGrim->JumpToAddresses(p_match_address_pair->original, p_match_address_pair->patched);
			}
		}
		return 0;
	}

#define ASSOCIATE_SOCKET_COUNT_BASE_FOR_IDA_SYNC 1234

	int AssociateSocketComplete(WORD,WORD,HWND,BOOL&)
	{
		dprintf("%s: AssociateSocketCount=%u\n",__FUNCTION__,AssociateSocketCount);
		if(AssociateSocketCount==ASSOCIATE_SOCKET_COUNT_BASE_FOR_IDA_SYNC)
		{
			::MessageBox(m_hWnd,"Original IDB is opened.","Information",MB_OK);
			PrintToLogView("Opening [%s]\r\n",m_TargetFileName.c_str());
			LaunchIDA((char *)m_TargetFileName.c_str());
		}else if(AssociateSocketCount==ASSOCIATE_SOCKET_COUNT_BASE_FOR_IDA_SYNC+1)
		{
			::MessageBox(m_hWnd,"Patched IDB is opened.\r\nIDA will be synced from now on.","Information",MB_OK);
			pDarunGrim->StartIDAListener( DARUNGRIM_PORT );
			pDarunGrim->CreateIDACommandProcessorThread();
		}
		AssociateSocketCount++;
		return 1;
	}

	void LaunchIDA(char *Filename)
	{
		//Create IDC file
		char *IDCFilename=WriteToTemporaryFile("static main()\n\
			{\n\
				Wait();\n\
				RunPlugin(\"DarunGrimPlugin\",1);\n\
				ConnectToDarunGrim();\n\
			}");
		if(IDCFilename)
		{
			//TODO: If the file is found, try to get it from the user
			//Launch IDA 
			PrintToLogView("Launching %s\n",Filename);
			PrintToLogView("Executing \"%s\" -S\"%s\" \"%s\"",m_IDAPath.c_str(), IDCFilename, Filename );
			Execute(FALSE,"\"%s\" -S\"%s\" \"%s\"", m_IDAPath.c_str(), IDCFilename, Filename);
			//Delete IDC file
			//DeleteFile(IDCFilename);
			free(IDCFilename);
		}
	}

	DWORD WINAPI PerformDiff()
	{
		PrintToLogView("Starting analysis...\r\n");

		pDarunGrim->PerformDiff(
			m_SourceFileName.c_str(), 0,
			m_TargetFileName.c_str(), 0,
			m_DiffFilename.c_str());

		SetWindowText(m_DiffFilename.c_str());

		pDiffMachine = pDarunGrim->GetDiffMachine();
		pDiffMachine->ShowFullMatched = OptionsDlg.ShowFullMatched;
		pDiffMachine->ShowNonMatched = OptionsDlg.ShowNonMatched;

		PrintToLogView("All operations finished...\r\n");
		
		PostMessage(
			WM_COMMAND,
			ID_SHOW_DIFF_RESULTS,NULL);

		PrintToLogView("Press close button.\r\n");

		return 1;
	}

	int ShowDiffResults(WORD,WORD,HWND,BOOL&)
	{
		//Show the results
		DisplayDiffResults();
		return 1;
	}

	LRESULT OnFileNew(WORD,WORD,HWND,BOOL&)
	{
		CSelectFilesDlg IDAConnectionDlg;
		if(IDAConnectionDlg.DoModal()==IDOK)
		{
			m_DiffFilename=IDAConnectionDlg.m_DGFFileName;
			m_SourceFileName=IDAConnectionDlg.m_SourceFileName;
			m_TargetFileName=IDAConnectionDlg.m_TargetFileName;

			if(m_DiffFilename.length()>0 && m_SourceFileName.length()>0 && m_TargetFileName.length()>0)
			{
				DWORD dwThreadId;
				CreateThread(NULL,0,PerformDiffThread,(PVOID)this,0,&dwThreadId);
				m_LogViewerDlg.ShowWindow(TRUE);
			}
		}
		return 0;
	}

	LRESULT OnFileOpen(WORD,WORD,HWND,BOOL&)
	{
		CFileDialog IDAConnectionDlgFile(TRUE,"dgf",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"DarunGrim Files (*.dgf)\0*.dgf\0All Files (*.*)\0*.*\0");
		if(IDAConnectionDlgFile.DoModal()==IDOK)
		{
			OpenDatabase(IDAConnectionDlgFile.m_szFileName);
		}
		return 0;
	}

	LRESULT OnDropFiles(UINT uMsg,WPARAM wParam,LPARAM lParam,BOOL& bHandled)
	{
		TCHAR szFilename[MAX_PATH];
		HDROP hDrop=(HDROP)wParam;
		SetActiveWindow();
		UINT iFileCount=::DragQueryFile(hDrop,(UINT)-1,NULL,0);
		for(UINT iFileIndex=0;iFileIndex<iFileCount;iFileIndex++)
		{
			::DragQueryFile(hDrop,iFileIndex,szFilename,sizeof(szFilename)/sizeof(TCHAR));
			if(strlen(szFilename)>3)
			{
				if(!stricmp(szFilename+strlen(szFilename)-4,".dgf"))
				{
					OpenDatabase(szFilename);
				}
			}
		}
		::DragFinish(hDrop);
		return 0;
	}

private:
	CIDAConnectionDlg IDAConnectionDlg;
	COptionsDlg OptionsDlg;

public:
	LRESULT OnOptions(WORD, WORD, HWND, BOOL&)
	{
		OptionsDlg.DoModal();

		if (pDiffMachine)
		{
			pDiffMachine->ShowFullMatched = OptionsDlg.ShowFullMatched;
			pDiffMachine->ShowNonMatched = OptionsDlg.ShowNonMatched;
		}
		
		return 0;
	}

	LRESULT OnIDAConnections(WORD, WORD, HWND, BOOL&)
	{
		if (pDarunGrim->GetSourceClientManager())
		{
			IDAConnectionDlg.SetDarunGrim(pDarunGrim);

			if(IDAConnectionDlg.DoModal()==IDOK)
			{
				m_SourceFileName=IDAConnectionDlg.m_SourceFileName;
				m_TargetFileName=IDAConnectionDlg.m_TargetFileName;
			}
		}else
		{
			::MessageBox(m_hWnd,"Please Open dgf file first.","Information",MB_OK);
		}
		return 0;
	}

	DWORD GetCurrentOffset(char *filename)
	{
		HANDLE hInFile=CreateFile(filename,   // file to open
			GENERIC_READ,         // open for reading
			FILE_SHARE_READ,      // share for reading
			NULL,                 // default security
			OPEN_EXISTING,        // existing file only
			FILE_ATTRIBUTE_NORMAL,// normal file
			NULL);                 // no attr. template
		if(hInFile==INVALID_HANDLE_VALUE) 
		{ 
			dprintf("Could not open file %s (error %u)\n",filename,GetLastError());
			return -1;
		}
		DWORD Offset=SetFilePointer(hInFile,0L,0L,FILE_END);
		CloseHandle(hInFile);
		return Offset;
	}

	int WriteOffsetLength(
		char *filename,
		DWORD TheSourceLength,
		DWORD TheTargetLength,
		DWORD ResultLength,
		BOOL bCreate

	)
	{
		HANDLE hOutFile=CreateFile(filename,// file to create
			GENERIC_WRITE,// open for writing
			0,// do not share
			NULL,// default security
			bCreate?CREATE_ALWAYS:OPEN_EXISTING,// overwrite existing
			FILE_ATTRIBUTE_NORMAL|// normal file
			NULL,// asynchronous I/O
			NULL); // no attr. template
		if(hOutFile==INVALID_HANDLE_VALUE) 
		{ 
			dprintf("Could not open file %s (error %u)\n",filename,GetLastError());
			return -1;
		}
		DWORD dwBytesWritten;
		BOOL status;

		status=WriteFile(hOutFile,
			&TheSourceLength,
			sizeof(DWORD),
			&dwBytesWritten,
			NULL); 
		status=WriteFile(hOutFile,
			&TheTargetLength,
			sizeof(DWORD),
			&dwBytesWritten,
			NULL); 
		status=WriteFile(hOutFile,
			&ResultLength,
			sizeof(DWORD),
			&dwBytesWritten,
			NULL); 
		CloseHandle(hOutFile);
		return 0;
	}

	int ReadOffsetLength(
		char *filename,
		DWORD *pTheSourceLength,
		DWORD *pTheTargetLength,
		DWORD *pResultLength
	)
	{
		HANDLE hInFile=CreateFile(filename,// file to create
			GENERIC_READ,// open for writing
			0,// do not share
			NULL,// default security
			OPEN_EXISTING,// overwrite existing
			FILE_ATTRIBUTE_NORMAL|// normal file
			NULL,// asynchronous I/O
			NULL); // no attr. template
		if(hInFile==INVALID_HANDLE_VALUE) 
		{ 
			dprintf("Could not open file %s (error %u)\n",filename,GetLastError());
			return -1;
		}
		DWORD dwBytesRead;
		BOOL status;

		status=ReadFile(hInFile,
			pTheSourceLength,
			sizeof(DWORD),
			&dwBytesRead,
			NULL); 
		status=ReadFile(hInFile,
			pTheTargetLength,
			sizeof(DWORD),
			&dwBytesRead,
			NULL); 
		status=ReadFile(hInFile,
			pResultLength,
			sizeof(DWORD),
			&dwBytesRead,
			NULL); 
		CloseHandle(hInFile);
		return 0;
	}

	void WriteToFile(HANDLE hFile, const char *format, ...)
	{
		va_list args;
		va_start(args, format);
		char Contents[1024] = { 0, };
		_vsnprintf(Contents, sizeof(Contents) / sizeof(char), format, args);
		va_end(args);

		if (hFile != INVALID_HANDLE_VALUE)
		{

			DWORD dwBytesWritten;
			BOOL fSuccess = WriteFile(hFile,
				Contents,
				strlen(Contents),
				&dwBytesWritten,
				NULL);
			if (!fSuccess)
			{
				printf("WriteFile failed with error %u.\n", GetLastError());
			}
		}
	}

	LRESULT OnShowBreakpoints(WORD, WORD, HWND, BOOL&)
	{
		PrintToLogView("Retrieving breakpoints...\r\n");

		BREAKPOINTS breakpoints = pDiffMachine->ShowUnidentifiedAndModifiedBlocks();

		CFileDialog dlgBreakPointFile(FALSE, "txt", NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, "*.txt");
		if (dlgBreakPointFile.DoModal() == IDOK)
		{
			PrintToLogView("Opening %s...\r\n", dlgBreakPointFile.m_szFileName);

			HANDLE hFile = CreateFile((LPTSTR)dlgBreakPointFile.m_szFileName,// file name 
				GENERIC_READ | GENERIC_WRITE,// open r-w 
				FILE_SHARE_READ,
				NULL,				// default security 
				OPEN_ALWAYS,		// overwrite existing
				FILE_ATTRIBUTE_NORMAL,// normal file 
				NULL);				// no template 
			if (hFile != INVALID_HANDLE_VALUE)
			{
				WriteToFile(hFile, "\r\n* Source Binary Breakpoints:\r\n");
				for (hash_set<DWORD>::iterator iter = breakpoints.SourceFunctionMap.begin(); iter != breakpoints.SourceFunctionMap.end(); iter++)
				{
					WriteToFile(hFile, "bp %x \".echo FUNCTION: %x;gc\"\r\n", *iter, *iter);
				}

				for (hash_set<DWORD>::iterator iter = breakpoints.SourceAddressMap.begin(); iter != breakpoints.SourceAddressMap.end(); iter++)
				{
					WriteToFile(hFile, "bp %x \".echo '    %x';gc\"\r\n", *iter, *iter);
				}

				WriteToFile(hFile, "\r\n* Target Binary Breakpoints:\r\n");
				for (hash_set<DWORD>::iterator iter = breakpoints.TargetFunctionMap.begin(); iter != breakpoints.TargetFunctionMap.end(); iter++)
				{
					WriteToFile(hFile, "bp %x \".echo FUNCTION: %x;gc\"\r\n", *iter, *iter);
				}

				for (hash_set<DWORD>::iterator iter = breakpoints.TargetAddressMap.begin(); iter != breakpoints.TargetAddressMap.end(); iter++)
				{
					WriteToFile(hFile, "bp %x \".echo '    %x';gc\"\r\n", *iter, *iter);
				}

				CloseHandle(hFile);

				PrintToLogView("Breakpoints saved.\r\n");
			}
		}
		m_LogViewerDlg.ShowWindow(TRUE);

		PrintToLogView("Press close button.\r\n");

		return 0;
	}

	LRESULT OnViewLogViewer(WORD,WORD,HWND,BOOL&)
	{
		m_LogViewerDlg.ShowWindow(TRUE);
		return 0;
	}

	LRESULT OpenDatabase(const char *Filename)
	{
		dprintf("%s: %s\n",__FUNCTION__,Filename);

		m_DiffFilename=Filename;

		if(m_DiffFilename.length()>0)
		{
			DWORD dwThreadId;
			CreateThread(NULL,0,OpenDatabaseThread,(PVOID)this,0,&dwThreadId);
			m_LogViewerDlg.ShowWindow(TRUE);
		}
		return 0;
	}

	DWORD WINAPI OpenDatabaseWorker()
	{
		PrintToLogView("Opening %s...\r\n",m_DiffFilename.c_str());
		SetWindowText(m_DiffFilename.c_str());

		pDarunGrim->Load(m_DiffFilename.c_str());

		pDiffMachine = pDarunGrim->GetDiffMachine();
		pDiffMachine->ShowFullMatched = OptionsDlg.ShowFullMatched;
		pDiffMachine->ShowNonMatched = OptionsDlg.ShowNonMatched;

		PrintToLogView("All operations finished...\r\n");

		PostMessage(
			WM_COMMAND,
			ID_SHOW_DIFF_RESULTS,NULL);
		PrintToLogView("Press close button.\r\n");

		return 1;
	}

	LRESULT OnFileExit(WORD,WORD,HWND,BOOL&)
	{
		PostMessage(WM_CLOSE);
		return 0;
	}

	LRESULT OnAppAbout(WORD,WORD,HWND,BOOL&)
	{
		CAboutDlg IDAConnectionDlg;
		IDAConnectionDlg.DoModal();
		return 0;
	}

	LRESULT OnZoomIn(WORD,WORD,HWND,BOOL&)
	{
		m_Zoom+=0.1f;
		m_lGraphVizView.SetZoomLevel(m_Zoom);
		m_rGraphVizView.SetZoomLevel(m_Zoom);
		return 1;
	}
	LRESULT OnZoomOut(WORD,WORD,HWND,BOOL&)
	{
		if(0.1<m_Zoom)
		{
			m_Zoom-=0.1f;
			m_lGraphVizView.SetZoomLevel(m_Zoom);
			m_rGraphVizView.SetZoomLevel(m_Zoom);
		}
		return 1;
	}
	LRESULT OnZoomActual(WORD,WORD,HWND,BOOL&)
	{
		m_Zoom=1.0f;
		m_lGraphVizView.SetZoomLevel(m_Zoom);
		m_rGraphVizView.SetZoomLevel(m_Zoom);
		return 1;
	}
};

int GraphViewSelectProxyCallback(DWORD address,DWORD ptr,DWORD index,int offset_x,int offset_y)
{
	CMainFrame *pCMainFrame=(CMainFrame *)ptr;
	pCMainFrame->GraphViewSelectCallback(address,index,offset_x,offset_y);
	return 0;
}

DWORD WINAPI PerformDiffThread(LPVOID pParam)
{
	CMainFrame *pCMainFrame=(CMainFrame *)pParam;
	pCMainFrame->PerformDiff();
	return 0;
}

DWORD WINAPI OpenDatabaseThread(LPVOID pParam)
{
	CMainFrame *pCMainFrame=(CMainFrame *)pParam;
	pCMainFrame->OpenDatabaseWorker();
	return 0;
}

#endif // !defined(AFX_MAINFRM_H__BBA5DFCA_6C1A_11D6_B657_0048548B09C5__INCLUDED_)
