#pragma once
#include "stdafx.h"

class COptionsDlg : public CDialogImpl<COptionsDlg>, public CWinDataExchange<COptionsDlg>
{
public:
	bool ShowFullMatched;
	bool ShowNonMatched;

public:
	BEGIN_MSG_MAP(CIDAConnectionDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnOKCmd)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
	END_MSG_MAP()
	
	BEGIN_DDX_MAP(CIDAConnectionDlg)
		DDX_CHECK(IDC_CHECK_SHOW_FULL_MATCHED, ShowFullMatched)
		DDX_CHECK(IDC_CHECK_SHOW_NON_MATCHED, ShowNonMatched)
	END_DDX_MAP()

	enum { IDD = IDD_DIALOG_OPTIONS };

	COptionsDlg():
		ShowFullMatched(false),
		ShowNonMatched(false)
	{

	}

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		DoDataExchange(FALSE);
		CenterWindow(GetParent());
		return TRUE;
	}

	LRESULT OnOKCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		DoDataExchange(TRUE);
		EndDialog(wID);

		printf("%d %d", ShowFullMatched, ShowNonMatched);
		return 0;
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		EndDialog(wID);
		return 0;
	}
};
