#pragma once

#define ID_SHOW_LOG_MESSAGE 1000

class CLogViewEdit:public CWindowImpl< CLogViewEdit, CEdit, CControlWinTraits >
{
public:
	DECLARE_WND_SUPERCLASS(_T("WTL_FilterEdit"), CEdit::GetWndClassName())  

	BEGIN_MSG_MAP(CFilterEdit)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		MESSAGE_HANDLER(WM_CHAR, OnChar)
		MESSAGE_HANDLER(WM_KEYDOWN, OnKeyDown)
		MESSAGE_HANDLER(WM_SETTEXT, OnSetText)
		MESSAGE_HANDLER(WM_PASTE, OnPaste)
	END_MSG_MAP()

	BOOL SubclassWindow(HWND hWnd)
	{
		ATLASSERT(m_hWnd == NULL);
		ATLASSERT(::IsWindow(hWnd));
		BOOL bRet = CWindowImpl< CLogViewEdit, CEdit, CControlWinTraits >::SubclassWindow(hWnd);
		return bRet;
	}

	LRESULT OnCreate(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& /*bHandled*/)
	{
		LRESULT lRes=DefWindowProc(uMsg, wParam, lParam);
		return lRes;
	}
	LRESULT OnChar(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& /*bHandled*/)
	{
		return 0;
	}

	LRESULT OnKeyDown(UINT /*uMsg*/, WPARAM wParam, LPARAM /*lParam*/, BOOL& bHandled)
	{
		return 0;
	}

	LRESULT OnSetText(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM lParam, BOOL& bHandled)
	{
		return 0;
	}

	LRESULT OnPaste(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& /*bHandled*/)
	{
		return 0;
	}
};

class CLogViwerDlg : public CDialogImpl<CLogViwerDlg>,public CDialogResize<CLogViwerDlg>
{
private:
	CLogViewEdit m_EditLog;
public:
	enum { IDD = IDD_DIALOG_LOG_VIEWER };

	BEGIN_MSG_MAP(CLogViwerDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnCloseCmd)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
		COMMAND_ID_HANDLER(ID_SHOW_LOG_MESSAGE,ShowLogMessageHandler)
		CHAIN_MSG_MAP(CDialogResize<CLogViwerDlg>)
	END_MSG_MAP()

	BEGIN_DLGRESIZE_MAP(CLogViwerDlg)
		 DLGRESIZE_CONTROL(IDC_EDIT_LOG, DLSZ_SIZE_X|DLSZ_SIZE_Y)
		 DLGRESIZE_CONTROL(IDOK,DLSZ_CENTER_X|DLSZ_MOVE_Y)
	END_DLGRESIZE_MAP()

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		CenterWindow(GetParent());
		DlgResize_Init();
		m_EditLog.SubclassWindow(GetDlgItem(IDC_EDIT_LOG));
		return TRUE;
	}

	void CloseDialog(int nVal)
	{
		DestroyWindow();
		PostQuitMessage(nVal);		
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		ShowWindow(FALSE);
		return 0;
	}

	BOOL PreTranslateMessage(MSG* pMsg)
	{
		return IsDialogMessage(pMsg);
	}

	BOOL OnIdle()
	{
		return FALSE;
	}

	int ShowLogMessageHandler(WORD wNotifyCode,WORD wID,HWND hWndCtl,BOOL& bHandled)
	{
		char *pText=(char *)hWndCtl;
		if(pText)
		{
			m_EditLog.AppendText(pText);
			free(pText);
		}
		return 1;
	}
};

