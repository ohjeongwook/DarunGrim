#if !defined(AFX_MAINFRM_H__BBA5DFCA_6C1A_11D6_B657_0048548B09C5__INCLUDED_)
#define AFX_MAINFRM_H__BBA5DFCA_6C1A_11D6_B657_0048548B09C5__INCLUDED_

#pragma once
#include "stdafx.h"
#include "CGraphVizWindow.h"

//DiffEngine
#include "IDAClientManager.h"
#include "Configuration.h"
#include "DiffMachine.h"
//DiffEngine
#include "CGraphVizProcessor.h"

#include "dprintf.h"

#include <hash_set>
#include <list>
#include <vector>
#include <hash_map>
#include <string>
using namespace std;
using namespace stdext;

#include "atlctrls.h"
#include "atlctrlw.h"

#include "DataBaseWriter.h"
#include "DBWrapper.h"

#include "ProcessUtils.h"

#include "resource.h"
#include "RC\resource.h"
#include "aboutdlg.h"
#include "SelectFilesDlg.h"
#include "LogViewerDlg.h"

#include "RegistryUtil.h"

int DebugLevel=0;
extern int GraphVizInterfaceProcessorDebugLevel;


int GraphViewSelectProxyCallback(DWORD address,DWORD ptr,DWORD index,int offset_x,int offset_y);
DWORD WINAPI GenerateDiffFromFilesThread(LPVOID pParam);
DWORD WINAPI OpenDGFWorkerThread(LPVOID pParam);

//CDisassemblyFileOpeningDlg
//pOneClientManagerTheSource->GetOriginalFilePath()
//pOneClientManagerTheTarget->GetOriginalFilePath()
//LaunchIDA
class CDisassemblyFileOpeningDlg : public CDialogImpl<CDisassemblyFileOpeningDlg>,public CWinDataExchange<CDisassemblyFileOpeningDlg>
{
private:
	CFileNameEdit m_SourceEdit;
	CFileNameEdit m_TargetEdit;

public:
	CString m_SourceFileName;
	CString m_TargetFileName;

	enum {IDD=IDD_DIALOG_DISASSEMBLY_FILE_OPENING};

	BEGIN_MSG_MAP(CDisassemblyFileOpeningDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnCloseCmd)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_SOURCE, OnButtonSourceCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_TARGET, OnButtonTargetCmd)
	END_MSG_MAP()

	BEGIN_DDX_MAP(CDisassemblyFileOpeningDlg)
		DDX_TEXT(IDC_EDIT_SOURCE,m_SourceFileName)
		DDX_TEXT(IDC_EDIT_TARGET,m_TargetFileName)
	END_DDX_MAP()

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		DoDataExchange(FALSE);
		m_SourceEdit.SubclassWindow(GetDlgItem(IDC_EDIT_SOURCE));
		m_TargetEdit.SubclassWindow(GetDlgItem(IDC_EDIT_TARGET));;

		//SetDlgItemText(IDC_EDIT_SOURCE,(char *)m_SourceFilemame);
		//SetDlgItemText(IDC_EDIT_TARGET,(char *)m_TargetFilemame);
		CenterWindow(GetParent());
		return TRUE;
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		DoDataExchange(TRUE);
		EndDialog(wID);
		return 0;
	}

	LRESULT OnButtonSourceCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CFileDialog dlgFile(TRUE,"*.*",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"All Files (*.*)\0*.*\0");
		if(dlgFile.DoModal()==IDOK)
		{
			//Update Inputbox
			SetDlgItemText(IDC_EDIT_SOURCE,dlgFile.m_szFileName);
		}
		return 0;
	}

	LRESULT OnButtonTargetCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CFileDialog dlgFile(TRUE,"*.*",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"All Files (*.*)\0*.*\0");
		if(dlgFile.DoModal()==IDOK)
		{
			//Update Inputbox
			SetDlgItemText(IDC_EDIT_TARGET,dlgFile.m_szFileName);
		}
		return 0;
	}

	void SetSourceFilename(char *Filename)
	{
		m_SourceFileName=Filename;
		
	}

	void SetTargetFilename(char *Filename)
	{
		m_TargetFileName=Filename;		
	}
};

typedef struct
{
	DWORD original;
	DWORD patched;
} MatchAddressPair;

enum {STATE_NONE,STATE_DGF_CREATED,STATE_DGF_OPENED,STATE_ORIGINAL_ANALYZED,STATE_PATCHED_ACCEPTED,STATE_ANALYSIS_COMPLETED};

class CMainFrame : public CFrameWindowImpl<CMainFrame>
{
private:
	char *m_IDAPath;
	char *m_LogFilename;

	string m_DatabaseFilename;
	string m_SourceFileName;
	string m_TargetFileName;

	CLogViwerDlg m_LogViewerDlg;

	DBWrapper m_DatabaseHandle;
	HANDLE hThreadOfAssociateSocketWithClientManagers;
	IDAClientManager *pOneClientManager;
	OneIDAClientManager *pOneClientManagerTheSource;
	OneIDAClientManager *pOneClientManagerTheTarget;
	DiffMachine *pDiffMachine;
	bool bDescendingSortInfos[10];
	list<DrawingInfo *> *DrawingInfoMap;
	vector<MatchAddressPair> BlockList;
	CCommandBarCtrl m_CmdBar;
	float m_Zoom;
	BOOL m_UseLegacyFileFormat;
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
	CSortListViewCtrl m_DiffListView;
	CSortListViewCtrl m_MatchedBlocksView;

	BEGIN_MSG_MAP(CMainFrame)
		MESSAGE_HANDLER(WM_CREATE,OnCreate)
		COMMAND_ID_HANDLER(ID_PANE_CLOSE,OnPaneClose)
		COMMAND_ID_HANDLER(ID_APP_EXIT,OnFileExit)
		COMMAND_ID_HANDLER(ID_FILE_NEW,OnFileNew)
		COMMAND_ID_HANDLER(ID_FILE_OPEN,OnFileOpen)
		COMMAND_ID_HANDLER(ID_OPEN_BINARIES_WITH_IDA,OnOpenBinariesWithIDA)		
		COMMAND_ID_HANDLER(ID_FILE_SAVE,OnFileSave)
		COMMAND_ID_HANDLER(ID_VIEW_LOGVIEWER,OnViewLogViewer)	
		COMMAND_ID_HANDLER(ID_ZOOM_IN,OnZoomIn)
		COMMAND_ID_HANDLER(ID_ZOOM_OUT,OnZoomOut)
		COMMAND_ID_HANDLER(ID_ZOOM_ACTUAL,OnZoomActual)
		COMMAND_ID_HANDLER(ID_FILE_EXPORT,OnExportSelections)
		COMMAND_ID_HANDLER(ID_START_ANALYZE_IDA_CLIENT_MANAGERS,AnalyzeIDAClientManagers)
		COMMAND_ID_HANDLER(ID_ASSOCIATE_SOCKET_COMPLETE,AssociateSocketComplete)
		COMMAND_ID_HANDLER(ID_SHOW_DIFF_RESULTS,ShowDiffResults)
		
		COMMAND_ID_HANDLER(ID_APP_ABOUT,OnAppAbout)
		NOTIFY_CODE_HANDLER(NM_DBLCLK,OnListViewDblClick)
		NOTIFY_CODE_HANDLER(LVN_COLUMNCLICK,OnListViewColumnClick)
		CHAIN_MSG_MAP(CFrameWindowImpl<CMainFrame>)
		MESSAGE_HANDLER(WM_DROPFILES,OnDropFiles)
	END_MSG_MAP()

	void SetDatabaseFilename(char *Filename)
	{
		CleanCDFStructures();
		m_DatabaseFilename=Filename;
		OpenDGF(m_DatabaseFilename.c_str());
	}

	~CMainFrame()
	{
		m_LogViewerDlg.CloseDialog(0);
		if(m_IDAPath)
			free(m_IDAPath);
		if(m_LogFilename)
			free(m_LogFilename);
	}

	LRESULT OnCreate(UINT,WPARAM,LPARAM,BOOL&)
	{
		m_State=STATE_NONE;

		m_UseLegacyFileFormat=FALSE;
		m_Zoom=1.0f;
		hThreadOfAssociateSocketWithClientManagers=INVALID_HANDLE_VALUE;
		pOneClientManager=NULL;
		pOneClientManagerTheSource=NULL;
		pOneClientManagerTheTarget=NULL;
		pDiffMachine=NULL;
		m_RetrieveClientManagersDatabase=FALSE;

		//Get ini file path
		std::string ConfFileName;
		char *InstallDir = GetRegValueString( "HKEY_LOCAL_MACHINE\\SOFTWARE\\DarunGrim2", "Install_Dir" );
		if( InstallDir )
		{
			ConfFileName = InstallDir;
			ConfFileName += "\\";
		}
		ConfFileName += "Conf.ini";
		//Get IDA Path
		m_IDAPath=NULL;
		
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
			m_IDAPath=_strdup(Buffer);
		}

		dprintf("m_IDAPath=[%s]\n",m_IDAPath);

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
		memset(bDescendingSortInfos,0,sizeof(bDescendingSortInfos));

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

	int GraphViewSelectCallback(DWORD address,DWORD index,int offset_x,int offset_y)
	{
		if(index==0)
		{
			if(pOneClientManagerTheSource)
			{
				pOneClientManagerTheSource->ShowAddress(address);
			}
		}
		else
		{
			if(pOneClientManagerTheTarget)
			{
				pOneClientManagerTheTarget->ShowAddress(address);
			}
		}
		MatchData *pMatchData=pDiffMachine->GetMatchData(index,address);
		/*
		dprintf("Fingerprint: %x\n",address);
		char *hex_str=pOneClientManagerTheSource->GetFingerPrintStr(address);
		if(hex_str)
		{
			DumpHex("Fingerprint",(PBYTE)hex_str,0);
			free(hex_str);
		}*/
		if(pMatchData)
		{
			dprintf("Fingerprint: %x\n",pMatchData->Addresses[index==1?0:1]);
			//DumpHex("Fingerprint",(PBYTE)pOneClientManagerTheTarget->GetFingerPrintStr(pMatchData->Addresses[1]),0);
			dprintf("Fingerprint Match Rate: %3.d%%\n",pMatchData->MatchRate);
			DWORD Address=pMatchData->Addresses[index==1?0:1];
			if(index==0)
			{
				if(pOneClientManagerTheTarget)
					pOneClientManagerTheTarget->ShowAddress(Address);
				m_rGraphVizView.ShowNode(Address,offset_x,offset_y);
			}else
			{
				if(pOneClientManagerTheSource)
					pOneClientManagerTheSource->ShowAddress(Address);
				m_lGraphVizView.ShowNode(Address,offset_x,offset_y);
			}
		}
		return 0;
	}

	int AddItemToDiffListView(
			char *the_source,
			int the_source_umatched,
			char *the_target,
			int the_target_umatched,
			int different,
			int matched,
			int lParam
			)
	{
		int nIndex=m_DiffListView.InsertItem(LVIF_TEXT|LVIF_PARAM,
			0,
			the_source,
			0,
			0,
			0,
			(LPARAM)lParam);

		char tmp[20];
		_snprintf(tmp,sizeof(tmp),"%10d",the_source_umatched);
		m_DiffListView.SetItemText(nIndex,1,tmp);
		m_DiffListView.SetItemText(nIndex,2,the_target);
		_snprintf(tmp,sizeof(tmp),"%10d",the_target_umatched);
		m_DiffListView.SetItemText(nIndex,3,tmp);
		_snprintf(tmp,sizeof(tmp),"%10d",different);
		m_DiffListView.SetItemText(nIndex,4,tmp);
		_snprintf(tmp,sizeof(tmp),"%10d",matched);
		m_DiffListView.SetItemText(nIndex,5,tmp);

		float match_rate=0.0;
		int all_blocks=matched*2+the_source_umatched+the_target_umatched+different*2;
		if(all_blocks>0)
			match_rate=(all_blocks-(the_source_umatched+the_target_umatched+different))*100/all_blocks;
		if(match_rate==0)
		{
			_snprintf(tmp,sizeof(tmp),"  0%%");
		}else
		{
			_snprintf(tmp,sizeof(tmp),"%3.d%%",(int)match_rate);
		}
		m_DiffListView.SetItemText(nIndex,6,tmp);
		return nIndex;
	}

	void DrawOnGraphVizWindow(int index,CGraphVizWindow *pGraphVizWindow,OneIDAClientManager *pOneClientManager,DWORD address)
	{
		CGraphVizProcessor *pGraphVizProcessor=new CGraphVizProcessor();
		if(address>0)
		{
			char name[100];
			_snprintf(name,sizeof(name),"%X",address);
			char *disasm_line=pOneClientManager->GetDisasmLines(address,0);

			
			char *font_color="black";
			char *fill_color="white";
			MatchData *pMatchData=pDiffMachine->GetMatchData(index,address);
			if(!pMatchData)
			{
				font_color="white";
				fill_color="crimson";
			}else
			{
				if(pMatchData && pMatchData->MatchRate!=100)
				{
					font_color="black";
					fill_color="yellow";
				}
			}
			pGraphVizProcessor->SetNodeData(address,name,disasm_line?disasm_line:"",font_color,fill_color,"12");
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
			DWORD *p_addresses=pOneClientManager->GetMappedAddresses(*address_list_iter,CREF_FROM,&addresses_number);
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
							char *disasm_line=pOneClientManager->GetDisasmLines(current_address,0);

							char *font_color="black";
							char *fill_color="white";
							MatchData *pMatchData=pDiffMachine->GetMatchData(index,current_address);
							if(!pMatchData)
							{
								font_color="white";
								fill_color="red";
							}else
							{
								if(pMatchData && pMatchData->MatchRate!=100)
								{
									font_color="black";
									fill_color="yellow";
								}
							}
							pGraphVizProcessor->SetNodeData(current_address,name,disasm_line?disasm_line:"",font_color,fill_color,"12");
							if(disasm_line)
								free(disasm_line);
						}
						pGraphVizProcessor->SetMapData(*address_list_iter,current_address);
					}
				}
				free(p_addresses);
			}
		}
		DrawingInfoMap=pGraphVizProcessor->GenerateDrawingInfo();
		delete pGraphVizProcessor;
		pGraphVizWindow->SetDrawingInfoMap(DrawingInfoMap);
	}


	LRESULT OnListViewDblClick(int idCtrl,LPNMHDR pnmh,BOOL& bHandled)
	{
		LPNMITEMACTIVATE pnmia=(LPNMITEMACTIVATE)pnmh;
		if(m_DiffListView.GetDlgCtrlID()==idCtrl)
		{
			m_MatchedBlocksView.DeleteAllItems();
			m_TabView.SetActivePage(1);
			FunctionMatchInfo match_info=pDiffMachine->GetFunctionMatchInfo((int)m_DiffListView.GetItemData(pnmia->iItem));
			m_lPane.SetTitle(match_info.TheSourceFunctionName);
			m_rPane.SetTitle(match_info.TheTargetFunctionName);

			list <DWORD> orig_addresses=pOneClientManagerTheSource->GetFunctionMemberBlocks(match_info.TheSourceAddress);
			list <DWORD> patched_addresses=pOneClientManagerTheTarget->GetFunctionMemberBlocks(match_info.TheTargetAddress);

			hash_set <DWORD> matched_addresses;
			list <DWORD>::iterator iter;
			for(iter=orig_addresses.begin();iter!=orig_addresses.end();iter++)
			{
				if(*iter>0)
				{
					char tmp[20];
					_snprintf(tmp,sizeof(tmp),"%X",*iter);

					int nIndex=m_MatchedBlocksView.InsertItem(LVIF_TEXT|LVIF_PARAM,
						0,
						tmp,
						0,
						0,
						0,
						(LPARAM)BlockList.size());
						//Fingerprint
					char *fingerprint=pOneClientManagerTheSource->GetFingerPrintStr(*iter);
					if(fingerprint)
					{
						m_MatchedBlocksView.SetItemText(nIndex,4,fingerprint);
						free(fingerprint);
					}

					MatchAddressPair match_address_pair;
					match_address_pair.original=*iter;
					match_address_pair.patched=0;
					MatchData *pMatchData=pDiffMachine->GetMatchData(0,*iter);
					if(pMatchData)
					{
						matched_addresses.insert(pMatchData->Addresses[1]);
						_snprintf(tmp,sizeof(tmp),"%X",pMatchData->Addresses[1]);
						m_MatchedBlocksView.SetItemText(nIndex,1,tmp);
						_snprintf(tmp,sizeof(tmp),"%3.d%%",pMatchData->MatchRate);
						m_MatchedBlocksView.SetItemText(nIndex,2,tmp);
						//Type
						m_MatchedBlocksView.SetItemText(nIndex,3,pDiffMachine->GetMatchTypeStr(pMatchData->Type));

						fingerprint=pOneClientManagerTheTarget->GetFingerPrintStr(pMatchData->Addresses[1]);
						if(fingerprint)
						{
							m_MatchedBlocksView.SetItemText(nIndex,5,fingerprint);
							free(fingerprint);
						}

						_snprintf(tmp,sizeof(tmp),"%X",pMatchData->UnpatchedParentAddress);
						m_MatchedBlocksView.SetItemText(nIndex,6,tmp);
						_snprintf(tmp,sizeof(tmp),"%X",pMatchData->PatchedParentAddress);
						m_MatchedBlocksView.SetItemText(nIndex,7,tmp);

						match_address_pair.patched=pMatchData->Addresses[1];
					}
					BlockList.push_back(match_address_pair);
				}
			}
			for(iter=patched_addresses.begin();iter!=patched_addresses.end();iter++)
			{
				if(matched_addresses.find(*iter)==matched_addresses.end() && *iter>0)
				{
					int nIndex=m_MatchedBlocksView.InsertItem(LVIF_TEXT|LVIF_PARAM,
						0,
						" ",
						0,
						0,
						0,
						(LPARAM)BlockList.size());
					char tmp[20];
					_snprintf(tmp,sizeof(tmp),"%X",*iter);

					m_MatchedBlocksView.SetItemText(nIndex,1,tmp);
					MatchAddressPair match_address_pair;
					match_address_pair.original=0;
					match_address_pair.patched=*iter;
					MatchData *pMatchData=pDiffMachine->GetMatchData(1,*iter);
					if(pMatchData)
					{
						_snprintf(tmp,sizeof(tmp),"%X",pMatchData->Addresses[0]);
						m_MatchedBlocksView.SetItemText(nIndex,0,tmp);
						match_address_pair.original=pMatchData->Addresses[0];
					}
					char *fingerprint=pOneClientManagerTheTarget->GetFingerPrintStr(*iter);
					if(fingerprint)
					{
						m_MatchedBlocksView.SetItemText(nIndex,5,fingerprint);
						free(fingerprint);
					}
					BlockList.push_back(match_address_pair);
				}
			}
			DrawOnGraphVizWindow(0,&m_lGraphVizView,pOneClientManagerTheSource,match_info.TheSourceAddress);
			DrawOnGraphVizWindow(1,&m_rGraphVizView,pOneClientManagerTheTarget,match_info.TheTargetAddress);
		}else if(m_MatchedBlocksView.GetDlgCtrlID()==idCtrl)
		{
			int pos=(int)m_MatchedBlocksView.GetItemData(pnmia->iItem);
			MatchAddressPair &match_address_pair=BlockList.at(pos);

			RECT rc;
			m_lGraphVizView.GetClientRect(&rc);
			m_lGraphVizView.ShowNode(match_address_pair.original,(rc.right-rc.left)/2,(rc.bottom-rc.top)/2);
			if(pOneClientManagerTheSource)
				pOneClientManagerTheSource->ShowAddress(match_address_pair.original);

			m_rGraphVizView.GetClientRect(&rc);
			m_rGraphVizView.ShowNode(match_address_pair.patched,(rc.right-rc.left)/2,(rc.bottom-rc.top)/2);
			if(pOneClientManagerTheTarget)
				pOneClientManagerTheTarget->ShowAddress(match_address_pair.patched);
		}
		return 0;
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
	
	LRESULT OnListViewColumnClick(int idCtrl,LPNMHDR pnmh,BOOL& bHandled)
	{
		if(m_DiffListView.GetDlgCtrlID()==idCtrl)
		{
			LPNMLISTVIEW lpn=(LPNMLISTVIEW)pnmh;
			bDescendingSortInfos[lpn->iSubItem]=bDescendingSortInfos[lpn->iSubItem]?0:1;
			m_DiffListView.SortItems(lpn->iSubItem,bDescendingSortInfos[lpn->iSubItem]);
		}else if(m_MatchedBlocksView.GetDlgCtrlID()==idCtrl)
		{
		}
		return 0;
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

	typedef struct {
		IDAClientManager *pOneClientManager;
		OneIDAClientManager *pOneClientManagerTheSource;
		OneIDAClientManager *pOneClientManagerTheTarget;
	} ClientManagers;

	static DWORD WINAPI AssociateSocketWithClientManagers(LPVOID pParam)
	{
		DBWrapper *OutputDB=&(((CMainFrame *)pParam)->m_DatabaseHandle);
		{
			IDAClientManager *pOneClientManager=new IDAClientManager(DARUNGRIM2_PORT);
			if(pOneClientManager->AssociateSocket(((CMainFrame *)pParam)->GetOneClientManagerTheSource(),((CMainFrame *)pParam)->RetrieveClientManagersDatabase()))
			{
				((CMainFrame *)pParam)->PostMessage(
					WM_COMMAND,
					ID_ASSOCIATE_SOCKET_COMPLETE,NULL);
				if(pOneClientManager->AssociateSocket(((CMainFrame *)pParam)->GetOneClientManagerTheTarget(),((CMainFrame *)pParam)->RetrieveClientManagersDatabase()))
				{
					((CMainFrame *)pParam)->PostMessage(
						WM_COMMAND,
						ID_ASSOCIATE_SOCKET_COMPLETE,NULL);
				}
			}
		}
		((CMainFrame *)pParam)->PostMessage(
			WM_COMMAND,
			ID_START_ANALYZE_IDA_CLIENT_MANAGERS,NULL);
		return 0;
	}

	void SetIDAClientManagers(
		IDAClientManager *pParamOneClientManager,
		OneIDAClientManager *pParamOneClientManagerTheSource,
		OneIDAClientManager *pParamOneClientManagerTheTarget)
	{
		pOneClientManager=pParamOneClientManager;
		pOneClientManagerTheSource=pParamOneClientManagerTheSource;
		pOneClientManagerTheTarget=pParamOneClientManagerTheTarget;
	}

	OneIDAClientManager *GetOneClientManagerTheSource()
	{
		return pOneClientManagerTheSource;
	}

	OneIDAClientManager *GetOneClientManagerTheTarget()
	{
		return pOneClientManagerTheTarget;
	}

	bool RetrieveClientManagersDatabase()
	{
		return m_RetrieveClientManagersDatabase;
	}

	void DisplayDiffResults()
	{
		m_DiffListView.DeleteAllItems();
		int MatchCount=pDiffMachine->GetFunctionMatchInfoCount();
		for(int i=0;i<MatchCount;i++)
		{
			FunctionMatchInfo match_info=pDiffMachine->GetFunctionMatchInfo(i);
			if(match_info.BlockType==FUNCTION_BLOCK)
			{
				int index=AddItemToDiffListView(
					match_info.TheSourceFunctionName,
					match_info.NoneMatchCountForTheSource,
					match_info.TheTargetFunctionName,
					match_info.NoneMatchCountForTheTarget,
					match_info.MatchCountWithModificationForTheSource,
					match_info.MatchCountForTheSource,
					i);
			}
		}
		//IDA Interaction
		//Create new thread?
		//pOneClientManager->SetMembers(pOneClientManagerTheSource,pOneClientManagerTheTarget,pDiffMachine);
		//pOneClientManager->ShowResultsOnIDA();
		//pOneClientManager->CreateIDACommandProcessor();
	}

	int AnalyzeIDAClientManagers(WORD,WORD,HWND,BOOL&)
	{
		if(m_RetrieveClientManagersDatabase)
		{
			pDiffMachine=new DiffMachine(pOneClientManagerTheSource,pOneClientManagerTheTarget);
			pDiffMachine->Analyze();
			pDiffMachine->Save(m_DatabaseHandle);
			DisplayDiffResults();
		}
		return 1;
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
			IDAClientManager *pOneClientManager=new IDAClientManager(DARUNGRIM2_PORT);
			//pOneClientManager->SetMembers(pOneClientManagerTheSource,pOneClientManagerTheTarget,pDiffMachine);
			//pOneClientManager->ShowResultsOnIDA();
			//pOneClientManager->CreateIDACommandProcessor();
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
				RunPlugin(\"DarunGrim2\",1);\n\
				ConnectToDarunGrim2();\n\
			}");
		if(IDCFilename)
		{
			//TODO: If the file is found, try to get it from the user
			//Launch IDA 
			PrintToLogView("Launching %s\n",Filename);
			PrintToLogView("Executing \"%s\" -S\"%s\" \"%s\"",m_IDAPath,IDCFilename,Filename);
			Execute(FALSE,"\"%s\" -S\"%s\" \"%s\"",m_IDAPath,IDCFilename,Filename);
			//Delete IDC file
			//DeleteFile(IDCFilename);
			free(IDCFilename);
		}
	}

	bool LaunchAssociateSocketWithClientManagersThread(bool RetrieveClientManagersDatabase)
	{
		AssociateSocketCount=0;
		if(hThreadOfAssociateSocketWithClientManagers!=INVALID_HANDLE_VALUE)
		{
			DWORD ExitCode;
			if(!(GetExitCodeThread(hThreadOfAssociateSocketWithClientManagers,&ExitCode) && ExitCode==STILL_ACTIVE))
			{
				hThreadOfAssociateSocketWithClientManagers=INVALID_HANDLE_VALUE;
			}
		}

		if(hThreadOfAssociateSocketWithClientManagers==INVALID_HANDLE_VALUE)
		{
			DWORD dwThreadId;
			m_RetrieveClientManagersDatabase=RetrieveClientManagersDatabase;
			hThreadOfAssociateSocketWithClientManagers=CreateThread(NULL,0,AssociateSocketWithClientManagers,(PVOID)this,0,&dwThreadId);

			if(!RetrieveClientManagersDatabase)
			{
				AssociateSocketCount=ASSOCIATE_SOCKET_COUNT_BASE_FOR_IDA_SYNC;
				PrintToLogView("Opening [%s]\r\n",m_SourceFileName.c_str());
				LaunchIDA((char *)m_SourceFileName.c_str());
			}
			return TRUE;
		}
		return FALSE;
	}

	DWORD WINAPI GenerateDiffFromFiles()
	{
		PrintToLogView("Starting analysis...\r\n");
		IDAClientManager aIDAClientManager;
		if(m_IDAPath)
			aIDAClientManager.SetIDAPath(m_IDAPath);
		aIDAClientManager.SetOutputFilename((char *)m_DatabaseFilename.c_str());
		if(m_LogFilename)
			aIDAClientManager.SetLogFilename(m_LogFilename);

		PrintToLogView("Analyzing source file [%s]\r\n",m_SourceFileName.c_str());
		
		aIDAClientManager.RunIDAToGenerateDB((char *)m_SourceFileName.c_str(),0,0);

		PrintToLogView("Analyzing target file [%s]\r\n",m_TargetFileName.c_str());
		aIDAClientManager.RunIDAToGenerateDB((char *)m_TargetFileName.c_str(),0,0);

		CleanCDFStructures();	
		SetWindowText(m_DatabaseFilename.c_str());
		PrintToLogView("Creating database...\r\n");
		m_DatabaseHandle.CreateDatabase((char *)m_DatabaseFilename.c_str());
		CreateTables(m_DatabaseHandle);

		//Initiate Analysis
		pDiffMachine=new DiffMachine();
		PrintToLogView("Retrieve signature data...\r\n");
		pDiffMachine->Retrieve(m_DatabaseHandle,TRUE,1,2);
		PrintToLogView("Start analysis...\r\n");
		pDiffMachine->Analyze();
		PrintToLogView("Saving results...\r\n");
		pDiffMachine->Save(m_DatabaseHandle);

		pOneClientManagerTheSource=pDiffMachine->GetTheSource();
		pOneClientManagerTheTarget=pDiffMachine->GetTheTarget();
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
		CSelectFilesDlg dlg;
		if(dlg.DoModal()==IDOK)
		{
			m_DatabaseFilename=dlg.m_DGFFileName;
			m_SourceFileName=dlg.m_SourceFileName;
			m_TargetFileName=dlg.m_TargetFileName;

			if(m_DatabaseFilename.length()>0 && m_SourceFileName.length()>0 && m_TargetFileName.length()>0)
			{
				DWORD dwThreadId;
				CreateThread(NULL,0,GenerateDiffFromFilesThread,(PVOID)this,0,&dwThreadId);
				m_LogViewerDlg.ShowWindow(TRUE);
			}
		}
		return 0;
	}

	/*
			//CFileDialog dlgFile(FALSE,"dgf",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"*.dgf");
			//Drag and drop original and patched binaries or idb files to the main DarunGrim2 window \r\nor 
			::MessageBox(m_hWnd,"Run IDA and send analysis info by executing DarunGrim2 Plugin(Alt-5).\nWhen data from two IDA sessions(unpatched first then patched) are received, the analysis will start automatically.","Information",MB_OK);
			CleanCDFStructures();
			m_DatabaseFilename=dlgFile.m_szFileName;
			SetWindowText(m_DatabaseFilename);

			m_DatabaseHandle.CreateDatabase(m_DatabaseFilename);
			CreateTables(m_DatabaseHandle);
			pOneClientManagerTheSource=new OneIDAClientManager(&m_DatabaseHandle);
			pOneClientManagerTheTarget=new OneIDAClientManager(&m_DatabaseHandle);
			LaunchAssociateSocketWithClientManagersThread(TRUE);
	*/

	LRESULT OnFileOpen(WORD,WORD,HWND,BOOL&)
	{
		CFileDialog dlgFile(TRUE,"dgf",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"DarunGrim Files (*.dgf)\0*.dgf\0All Files (*.*)\0*.*\0");
		if(dlgFile.DoModal()==IDOK)
		{
			CleanCDFStructures();
			OpenDGF(dlgFile.m_szFileName);
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
			//::MessageBox(m_hWnd,szFilename,"Information",MB_OK);
			if(strlen(szFilename)>3)
			{
				if(!stricmp(szFilename+strlen(szFilename)-4,".dgf"))
				{
					//Open dgf
					CleanCDFStructures();
					OpenDGF(szFilename);
				}/*else if(m_State==STATE_DGF_CREATED || m_State==STATE_ORIGINAL_ANALYZED)
				{
					//Open DLL or IDB using IDA
					switch(m_State)
					{
						case STATE_DGF_CREATED:
							if(m_OriginalFilename)
								free(m_OriginalFilename);
							m_OriginalFilename=_strdup(szFilename);
							m_State=STATE_ORIGINAL_ANALYZED;
							break;
						case STATE_ORIGINAL_ANALYZED:
							{
								if(m_PatchedFilename)
									free(m_PatchedFilename);
								m_PatchedFilename=_strdup(szFilename);

								IDAClientManager aIDAClientManager;
								aIDAClientManager.SetOutputFilename(m_DatabaseFilename);
								aIDAClientManager.RunIDAToGenerateDB(m_OriginalFilename,0,0);
								aIDAClientManager.RunIDAToGenerateDB(m_PatchedFilename,0,0);
								//Initiate Analysis
								pDiffMachine=new DiffMachine();
								pDiffMachine->Retrieve(m_DatabaseHandle,TRUE,1,2);
								pDiffMachine->Analyze();
								pDiffMachine->Save(m_DatabaseHandle);

								//Show the results
								DisplayDiffResults();

								m_State=STATE_PATCHED_ACCEPTED;
							}
							break;
					}
				}*/
			}
		}
		::DragFinish(hDrop);
		return 0;
	}

	LRESULT OnOpenBinariesWithIDA(WORD,WORD,HWND,BOOL&)
	{
		if(pOneClientManagerTheSource && pOneClientManagerTheTarget)
		{
			//IDD_DIALOG_DISASSEMBLY_FILE_OPENING

			//TODO: Ask user to confirm whether to open the ida files			
			CDisassemblyFileOpeningDlg dlg;
			if(pOneClientManagerTheSource && pOneClientManagerTheSource->GetOriginalFilePath())
				dlg.SetSourceFilename(pOneClientManagerTheSource->GetOriginalFilePath());
			if(pOneClientManagerTheTarget && pOneClientManagerTheTarget->GetOriginalFilePath())
				dlg.SetTargetFilename(pOneClientManagerTheTarget->GetOriginalFilePath());
			if(dlg.DoModal()==IDOK)
			{
				::MessageBox(m_hWnd,"DarunGrim2 will try to launch relevant IDA sessions. But if it fails for some reason just open two relevant IDA sessions and run DarunGrim2 Plugin(Alt-5) one by one(orignal first, patched one next).\nWhen two IDA sessions(unpatched first then patched) are attached, the graph browsing will be synchronized with the IDA disassembly windows.","Information",MB_OK);
				m_SourceFileName=dlg.m_SourceFileName;
				m_TargetFileName=dlg.m_TargetFileName;
				LaunchAssociateSocketWithClientManagersThread(FALSE);
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

	LRESULT OnFileSave(WORD,WORD,HWND,BOOL&)
	{
		CFileDialog dlgFile(FALSE,"dgf",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"*.dgf");
		if(dlgFile.DoModal()==IDOK)
		{
			SaveCDFile(dlgFile.m_szFileName);
		}
		return 0;
	}

	LRESULT OnViewLogViewer(WORD,WORD,HWND,BOOL&)
	{
		m_LogViewerDlg.ShowWindow(TRUE);
		return 0;
	}

	LRESULT OnExportSelections(WORD,WORD,HWND,BOOL&)
	{
		CFileDialog dlgFile(FALSE,"dgf",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"*.dgf");
		if(dlgFile.DoModal()==IDOK)
		{
			SaveCDFile(dlgFile.m_szFileName,TRUE);
		}
		return 0;
	}

	void CleanCDFStructures()
	{
		if(pOneClientManagerTheSource)
		{
			delete pOneClientManagerTheSource;
			pOneClientManagerTheSource=NULL;
		}
		if(pOneClientManagerTheTarget)
		{
			delete pOneClientManagerTheTarget;
			pOneClientManagerTheTarget=NULL;
		}
		if(pDiffMachine)
		{
			delete pDiffMachine;
			pDiffMachine=NULL;
		}
		if(pDiffMachine)
		{
			delete pOneClientManager;
			pOneClientManager=NULL;
		}
	}

	LRESULT OpenDGF(const char *Filename)
	{
		dprintf("%s: %s\n",__FUNCTION__,Filename);

		m_DatabaseFilename=Filename;


		if(m_DatabaseFilename.length()>0)
		{
			DWORD dwThreadId;
			CreateThread(NULL,0,OpenDGFWorkerThread,(PVOID)this,0,&dwThreadId);
			m_LogViewerDlg.ShowWindow(TRUE);
		}
		return 0;
	}

	DWORD WINAPI OpenDGFWorker()
	{
		PrintToLogView("Opening %s...\r\n",m_DatabaseFilename.c_str());
#ifdef USE_LEGACY_MAP
		DWORD TheSourceLength;
		DWORD TheTargetLength;
		DWORD ResultLength;
		ReadOffsetLength(
			Filename,
			&TheSourceLength,
			&TheTargetLength,
			&ResultLength
		);

		pOneClientManagerTheSource=new OneIDAClientManager(Filename);
		DWORD CurrentOffset=sizeof(DWORD)*3;
		pOneClientManagerTheSource->Retrieve(Filename,CurrentOffset,TheSourceLength);

		CurrentOffset+=TheSourceLength;
		pOneClientManagerTheTarget=new OneIDAClientManager(Filename);
 		pOneClientManagerTheTarget->Retrieve(Filename,CurrentOffset,TheTargetLength);
		CurrentOffset+=TheTargetLength;

		pDiffMachine=new DiffMachine(pOneClientManagerTheSource,pOneClientManagerTheTarget);
		pDiffMachine->Retrieve(Filename,DiffMachineFileSQLiteFormat);
		CurrentOffset+=ResultLength;
#else
		SetWindowText(m_DatabaseFilename.c_str());

		m_DatabaseHandle.CreateDatabase((char *)m_DatabaseFilename.c_str());
		CreateTables(m_DatabaseHandle);
		pDiffMachine=new DiffMachine();
		pDiffMachine->Retrieve(m_DatabaseHandle);
		pOneClientManagerTheSource=pDiffMachine->GetTheSource();
		pOneClientManagerTheTarget=pDiffMachine->GetTheTarget();
#endif

		PrintToLogView("All operations finished...\r\n");
		PostMessage(
			WM_COMMAND,
			ID_SHOW_DIFF_RESULTS,NULL);
		PrintToLogView("Press close button.\r\n");

		return 1;
	}

	LRESULT SaveCDFile(char *filename,bool bSelectedOnly=FALSE)
	{
		hash_set <DWORD> *pTheSourceAddresses=NULL;
		hash_set <DWORD> *pTheTargetAddresses=NULL;
		hash_set <DWORD> TheSourceAddresses;
		hash_set <DWORD> TheTargetAddresses;
		if(bSelectedOnly)
		{
			pTheSourceAddresses=&TheSourceAddresses;
			pTheTargetAddresses=&TheTargetAddresses;
			//List selected items
			for(int i=0;i<m_DiffListView.GetItemCount();i++)
			{
				if(m_DiffListView.GetCheckState(i))
				{
					//match infos indexes that is selected
					//Code block addresses for the_source/the_target
					FunctionMatchInfo match_info=pDiffMachine->GetFunctionMatchInfo((int)m_DiffListView.GetItemData(i));
					list <DWORD>::iterator address_iterator;

					list <DWORD> addresses;
					addresses=pOneClientManagerTheSource->GetFunctionMemberBlocks(match_info.TheSourceAddress);
					for(address_iterator=addresses.begin();
						address_iterator!=addresses.end();
						address_iterator++)
					{
						dprintf("TheSource Address: %x\n",*address_iterator);
						TheSourceAddresses.insert(*address_iterator);
					}
					addresses=pOneClientManagerTheTarget->GetFunctionMemberBlocks(match_info.TheTargetAddress);
					for(address_iterator=addresses.begin();
						address_iterator!=addresses.end();
						address_iterator++)
					{
						dprintf("TheTarget Address: %x\n",*address_iterator);
						TheTargetAddresses.insert(*address_iterator);
					}
				}
			}
		}
		if(m_UseLegacyFileFormat)
		{
			WriteOffsetLength(filename,0,0,0,TRUE);
			pOneClientManagerTheSource->Save(filename,0L,FILE_END,pTheSourceAddresses);
			DWORD TheSourceLength=GetCurrentOffset(filename);

			pOneClientManagerTheTarget->Save(filename,0L,FILE_END,pTheTargetAddresses);
			DWORD TheTargetLength=GetCurrentOffset(filename);

			pDiffMachine->Save(filename,DiffMachineFileBinaryFormat,0L,FILE_END,pTheSourceAddresses,pTheTargetAddresses);

			DWORD ResultLength=GetCurrentOffset(filename);

			ResultLength-=TheTargetLength;
			TheTargetLength-=TheSourceLength;
			TheSourceLength-=sizeof(DWORD)*3;
			WriteOffsetLength(filename,TheSourceLength,TheTargetLength,ResultLength,FALSE);
		}else
		{
			pDiffMachine->Save(filename,DiffMachineFileSQLiteFormat,0L,FILE_END,pTheSourceAddresses,pTheTargetAddresses);
		}
		return 0;
	}

	LRESULT OnFileExit(WORD,WORD,HWND,BOOL&)
	{
		PostMessage(WM_CLOSE);
		return 0;
	}

	LRESULT OnAppAbout(WORD,WORD,HWND,BOOL&)
	{
		CAboutDlg dlg;
		dlg.DoModal();
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

DWORD WINAPI GenerateDiffFromFilesThread(LPVOID pParam)
{
	CMainFrame *pCMainFrame=(CMainFrame *)pParam;
	pCMainFrame->GenerateDiffFromFiles();
	return 0;
}

DWORD WINAPI OpenDGFWorkerThread(LPVOID pParam)
{
	CMainFrame *pCMainFrame=(CMainFrame *)pParam;
	pCMainFrame->OpenDGFWorker();
	return 0;
}

#endif // !defined(AFX_MAINFRM_H__BBA5DFCA_6C1A_11D6_B657_0048548B09C5__INCLUDED_)
