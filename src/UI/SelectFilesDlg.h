// SelectFilesDlg.h : interface of the SelectFilesDlg class

#pragma once
#include <string>
using namespace std;
using namespace stdext;
#include <atlddx.h>

class CFileNameEdit:public CWindowImpl<CFileNameEdit,CEdit,CControlWinTraits >
{
public:
	DECLARE_WND_SUPERCLASS(_T("WTL_FilterEdit"),CEdit::GetWndClassName())  

	BEGIN_MSG_MAP(CFilterEdit)
		MESSAGE_HANDLER(WM_CREATE,OnCreate)
		MESSAGE_HANDLER(WM_DROPFILES,OnDropFiles)
	END_MSG_MAP()
	LRESULT OnCreate(UINT uMsg,WPARAM wParam,LPARAM lParam,BOOL& /*bHandled*/)
	{
		LRESULT lRes=DefWindowProc(uMsg,wParam,lParam);
		return lRes;
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
			SetWindowText(szFilename);
			//::MessageBox(m_hWnd,szFilename,"Information",MB_OK);
		}
		::DragFinish(hDrop);
		return 0;
	}
};

class CSelectFilesDlg : public CDialogImpl<CSelectFilesDlg>,public CWinDataExchange<CSelectFilesDlg>
{
private:
	CFileNameEdit m_SourceEdit;
	CFileNameEdit m_TargetEdit;
	CFileNameEdit m_DGFEdit;
public:
	CString m_SourceFileName;
	CString m_TargetFileName;
	CString m_DGFFileName;

	enum {IDD=IDD_DIALOG_SELECT_FILES};

	BEGIN_MSG_MAP(CSelectFilesDlg)
		MESSAGE_HANDLER(WM_INITDIALOG,OnInitDialog)
		COMMAND_ID_HANDLER(IDOK,OnCloseCmd)
		COMMAND_ID_HANDLER(IDCANCEL,OnCloseCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_SOURCE,OnButtonSourceCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_TARGET,OnButtonTargetCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_DGF,OnButtonDGFCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_SOURCE_TRANSFER,OnButtonSourceTransferCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_TARGET_TRANSFER,OnButtonTargetTransferCmd)
	END_MSG_MAP()

	BEGIN_DDX_MAP(CSelectFilesDlg)
		DDX_TEXT(IDC_EDIT_SOURCE,m_SourceFileName)
		DDX_TEXT(IDC_EDIT_TARGET,m_TargetFileName)
		DDX_TEXT(IDC_EDIT_DGF,m_DGFFileName)
	END_DDX_MAP()

	LRESULT OnInitDialog(UINT /*uMsg*/,WPARAM /*wParam*/,LPARAM /*lParam*/,BOOL& /*bHandled*/)
	{
		DoDataExchange(FALSE);
		m_SourceEdit.SubclassWindow(GetDlgItem(IDC_EDIT_SOURCE));
		m_TargetEdit.SubclassWindow(GetDlgItem(IDC_EDIT_TARGET));;
		m_DGFEdit.SubclassWindow(GetDlgItem(IDC_EDIT_DGF));;
		CenterWindow(GetParent());
		return TRUE;
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/,WORD wID,HWND /*hWndCtl*/,BOOL& /*bHandled*/)
	{
		DoDataExchange(TRUE);
		EndDialog(wID);
		return 0;
	}

	LRESULT OnButtonSourceCmd(WORD /*wNotifyCode*/,WORD wID,HWND /*hWndCtl*/,BOOL& /*bHandled*/)
	{
		CFileDialog dlgFile(TRUE,"*.*",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"All Files (*.*)\0*.*\0");
		if(dlgFile.DoModal()==IDOK)
		{
			//Update Inputbox
			SetDlgItemText(IDC_EDIT_SOURCE,dlgFile.m_szFileName);
		}
		return 0;
	}

	LRESULT OnButtonTargetCmd(WORD /*wNotifyCode*/,WORD wID,HWND /*hWndCtl*/,BOOL& /*bHandled*/)
	{
		CFileDialog dlgFile(TRUE,"*.*",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"All Files (*.*)\0*.*\0");
		if(dlgFile.DoModal()==IDOK)
		{
			//Update Inputbox
			SetDlgItemText(IDC_EDIT_TARGET,dlgFile.m_szFileName);			
		}
		return 0;
	}

	LRESULT OnButtonDGFCmd(WORD /*wNotifyCode*/,WORD wID,HWND /*hWndCtl*/,BOOL& /*bHandled*/)
	{
		CFileDialog dlgFile(FALSE,"dgf",NULL,OFN_HIDEREADONLY|OFN_OVERWRITEPROMPT,"*.dgf");
		if(dlgFile.DoModal()==IDOK)
		{
			//Update Inputbox
			SetDlgItemText(IDC_EDIT_DGF,dlgFile.m_szFileName);
		}
		return 0;
	}

	LRESULT OnButtonSourceTransferCmd(WORD /*wNotifyCode*/,WORD wID,HWND /*hWndCtl*/,BOOL& /*bHandled*/)
	{
		//TODO: Get Data from IDA Session -> callback
		//TODO: Update Inputbox and disable
		return 0;
	}

	LRESULT OnButtonTargetTransferCmd(WORD /*wNotifyCode*/,WORD wID,HWND /*hWndCtl*/,BOOL& /*bHandled*/)
	{
		//TODO: Get Data from IDA Session -> callback
		//TODO: Update Inputbox and disable
		return 0;
	}
};
