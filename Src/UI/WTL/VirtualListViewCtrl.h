#pragma once

class VirtualListDisplayItem
{
public:
	string Items[10];
	int id;
};


template <class T>
class CVirtualListViewCtrl : public CWindowImpl<CVirtualListViewCtrl<T>, CListViewCtrl>
{
public:
	CVirtualListViewCtrl()
	{
	}

	~CVirtualListViewCtrl()
	{
	}

	BOOL PreTranslateMessage(MSG* pMsg) { pMsg; return FALSE; }

	BEGIN_MSG_MAP(CWTLVirtualList)
		MESSAGE_HANDLER(WM_CREATE, OnCreate)
		REFLECTED_NOTIFY_CODE_HANDLER(LVN_GETDISPINFO, OnLVGetDispInfo)
		DEFAULT_REFLECTION_HANDLER()
	END_MSG_MAP()

	HWND Create(HWND hWndParent, ATL::_U_RECT rect = NULL, LPCTSTR szWindowName = NULL,
		DWORD dwStyle = 0, DWORD dwExStyle = 0, ATL::_U_MENUorID MenuOrID = 0U,
		LPVOID lpCreateParam = NULL)
	{
		dwStyle |= LVS_OWNERDATA; 
		dwStyle |= LVS_REPORT;
		dwStyle |= LVS_SHOWSELALWAYS;
		dwStyle |= LVS_SINGLESEL;

		return CWindowImpl<CVirtualListViewCtrl, CListViewCtrl>::Create(hWndParent,
			rect.m_lpRect, szWindowName, dwStyle, dwExStyle, MenuOrID.m_hMenu,
			lpCreateParam);
	}

	LRESULT Init(HWND hWnd)
	{
		if (hWnd == NULL) return 0; else SubclassWindow(hWnd);

		DWORD dwStyle = LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL;
		ModifyStyle(0, dwStyle);

		BOOL b = 0;
		OnCreate(0, 0, 0, (BOOL&)b);

		return 0;
	}

	LRESULT OnCreate(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
	{
		DWORD dwExStyle = 0;
		dwExStyle |= LVS_EX_GRIDLINES;
		dwExStyle |= LVS_EX_FULLROWSELECT;
		dwExStyle |= LVS_EX_DOUBLEBUFFER; // reduces flicker
		dwExStyle |= LVS_EX_HEADERDRAGDROP; // allow column rearranging
		SetExtendedListViewStyle(dwExStyle);

		bHandled = FALSE;
		return 0;
	}

private:
	vector<VirtualListDisplayItem *> *DisplayItemList;

public:
	void SetData(vector<VirtualListDisplayItem *> *NewDisplayItemList)
	{
		DisplayItemList = NewDisplayItemList;
	}

	int GetID(int i)
	{
		return DisplayItemList->at(i)->id;
	}

	LRESULT OnLVGetDispInfo(int, LPNMHDR pNMHDR, BOOL&)
	{
		if (pNMHDR->hwndFrom != m_hWnd) return 0;

		LVITEM* pItem = &((NMLVDISPINFO*)pNMHDR)->item;
		if (pItem->mask & LVIF_TEXT)
		{
			printf("%d %d\n", pItem->iItem, pItem->iSubItem);
			
			if (pItem->iItem < DisplayItemList->size())
			{
				const char *data = DisplayItemList->at(pItem->iItem)->Items[pItem->iSubItem].c_str();
				strcpy(pItem->pszText, data);
			}
		}

		return 0;
	}
};
