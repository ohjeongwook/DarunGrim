#pragma once
#include "stdafx.h"
#include "IDAClientManager.h"
#include "DiffMachine.h"

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
#include "aboutdlg.h"
#include "SelectFilesDlg.h"
#include "LogViewerDlg.h"

class CIDAConnectionDlg : public CDialogImpl<CIDAConnectionDlg>, public CWinDataExchange<CIDAConnectionDlg>
{
private:
	CFileNameEdit m_SourceEdit;
	CFileNameEdit m_TargetEdit;
	CLogViewEdit m_LogView;
public:
	CString m_SourceFileName;
	CString m_TargetFileName;

	enum { IDD = IDD_DIALOG_DISASSEMBLY_FILE_OPENING };

	BEGIN_MSG_MAP(CIDAConnectionDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnCloseCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_SOURCE, OnButtonSourceCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_TARGET, OnButtonTargetCmd)

		COMMAND_ID_HANDLER(IDC_BUTTON_SOURCE_CONNECTION, OnButtonSourceConnectionCmd)
		COMMAND_ID_HANDLER(IDC_BUTTON_TARGET_CONNECTION, OnButtonTargetConnectionCmd)

		COMMAND_ID_HANDLER(ID_ACCEPT_COMPLETE, ShowLogMessageHandler)
		
		COMMAND_ID_HANDLER(ID_SHOW_SOURCE_TEXT, ShowSourceText)
		COMMAND_ID_HANDLER(ID_SHOW_TARGET_TEXT, ShowTargetText)
	END_MSG_MAP()

	BEGIN_DDX_MAP(CIDAConnectionDlg)
		DDX_TEXT(IDC_EDIT_SOURCE, m_SourceFileName)
		DDX_TEXT(IDC_EDIT_TARGET, m_TargetFileName)
	END_DDX_MAP()

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		DoDataExchange(FALSE);
		m_LogView.SubclassWindow(GetDlgItem(IDC_LOG_VIEW));
		m_SourceEdit.SubclassWindow(GetDlgItem(IDC_EDIT_SOURCE));
		m_TargetEdit.SubclassWindow(GetDlgItem(IDC_EDIT_TARGET));;
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
		CFileDialog dlgFile(TRUE, "*.*", NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, "All Files (*.*)\0*.*\0");
		if (dlgFile.DoModal() == IDOK)
		{
			SetDlgItemText(IDC_EDIT_SOURCE, dlgFile.m_szFileName);
		}
		return 0;
	}

	LRESULT OnButtonTargetCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CFileDialog dlgFile(TRUE, "*.*", NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT, "All Files (*.*)\0*.*\0");
		if (dlgFile.DoModal() == IDOK)
		{
			SetDlgItemText(IDC_EDIT_TARGET, dlgFile.m_szFileName);
		}
		return 0;
	}

	static DWORD WINAPI AcceptIDAClient(LPVOID pParam)
	{
		CIDAConnectionDlg *pThis = (CIDAConnectionDlg *)pParam;
		IDAClientManager *pIDAClientManager = new IDAClientManager();
		OneIDAClientManager *pCurrentIDAClientManager = pThis->GetCurrentClientManager();
		pIDAClientManager->StartIDAListener(DARUNGRIM_PORT);
		
		int message_id = pThis->GetShowTextMessageId();

		pThis->PostMessage(
			WM_COMMAND,
			message_id, (LPARAM) _strdup("Listening..."));

		if (pIDAClientManager->AcceptIDAClient(pThis->GetCurrentClientManager(), false))
		{
			pThis->PostMessage(
				WM_COMMAND,
				ID_ACCEPT_COMPLETE, (LPARAM)_strdup("New connection accepted.\n"));
		}
		else
		{
			pThis->PostMessage(
				WM_COMMAND,
				ID_ACCEPT_COMPLETE, (LPARAM)_strdup("Connection failed.\n"));
		}

		pIDAClientManager->StopIDAListener();

		string input_name = pThis->GetCurrentClientManager()->GetInputName();
		pThis->PostMessage(
			WM_COMMAND,
			message_id, (LPARAM)_strdup(input_name.c_str()));

		return 0;
	}

	int ShowLogMessageHandler(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		char *text = (char *)hWndCtl;
		if (text)
		{
			m_LogView.AppendText(text);
			free(text);
		}
		return 1;
	}

	int ShowSourceText(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		char *text = (char *)hWndCtl;

		if (text)
		{
			SetDlgItemText(IDC_EDIT_SOURCE, text);
			free(text);
		}
		return 1;
	}


	int ShowTargetText(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		char *text = (char *)hWndCtl;

		if (text)
		{
			SetDlgItemText(IDC_EDIT_TARGET, text);
			free(text);
		}
		return 1;
	}

	LRESULT OnButtonSourceConnectionCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		DWORD dwThreadId;

		m_LogView.AppendText("Open source idb and run DarunGrim plugin.\n");

		ShowTextMessageId = ID_SHOW_SOURCE_TEXT;
		pCurrentClientManager = pSourceClientManager;
		HANDLE hAcceptClientThread = CreateThread(NULL, 0, AcceptIDAClient, (PVOID)this, 0, &dwThreadId);
		return 0;
	}

	LRESULT OnButtonTargetConnectionCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		DWORD dwThreadId;

		m_LogView.AppendText("Open target idb and run DarunGrim plugin.\n");

		ShowTextMessageId = ID_SHOW_TARGET_TEXT;
		pCurrentClientManager = pTargetClientManager;
		HANDLE hAcceptClientThread = CreateThread(NULL, 0, AcceptIDAClient, (PVOID)this, 0, &dwThreadId);
		return 0;
	}

	void SetSourceFilename(char *Filename)
	{
		m_SourceFileName = Filename;

	}

	void SetTargetFilename(char *Filename)
	{
		m_TargetFileName = Filename;
	}

private:
	void *Param;
	OneIDAClientManager *pSourceClientManager;
	OneIDAClientManager *pTargetClientManager;
	OneIDAClientManager *pCurrentClientManager;
	int ShowTextMessageId;
public:
	void SetParentClass(void *param)
	{
		Param = param;
	}

	void SetSourceClientManager(OneIDAClientManager *pNewSourceClientManager)
	{
		pSourceClientManager = pNewSourceClientManager;
	}

	void SetTargetClientManager(OneIDAClientManager *pNewTargetClientManager)
	{
		pTargetClientManager = pNewTargetClientManager;
	}

	OneIDAClientManager *GetCurrentClientManager()
	{
		return pCurrentClientManager;
	}

	int GetShowTextMessageId()
	{
		return ShowTextMessageId;
	}
};