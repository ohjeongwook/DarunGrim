#pragma once
#include <atlbase.h>
#include <atlapp.h>
#include <atlwin.h>
 
#include <atlcrack.h>
#include <atlmisc.h>
#include <atlframe.h>
#include <atlscrl.h>
#include <hash_map>
#include <list>
using namespace std;
using namespace stdext;

#ifdef dprintf
#include "dprintf.h"
#else
#define dprintf printf
#endif
#include "DrawingInfo.h"

#include <AtlGdi.h>

class CMemDC : public CDC
{
private:
	int DebugLevel;
public:
	CDCHandle m_OriginalHDC; //Owner DC
	CBitmap m_MemBitMap; //Offscreen bitmap
	CBitmapHandle m_OrigMemBitMap; //Originally selected bitmap
	RECT m_rc; //Rectangle of drawing area

	CMemDC(HDC hDC,LPRECT pRect=NULL)
	{
		DebugLevel=0;
		ATLASSERT(hDC!=NULL);
		m_OriginalHDC=hDC;
		if(pRect!=NULL)
			m_rc=*pRect; 
		else
			m_OriginalHDC.GetClipBox(&m_rc);

		if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: %d,%d,%d,%d\n",__FUNCTION__,m_rc.left,m_rc.right-m_rc.left,m_rc.top,m_rc.bottom-m_rc.top);
		CreateCompatibleDC(m_OriginalHDC);
		::LPtoDP(m_OriginalHDC,(LPPOINT)&m_rc,sizeof(RECT)/sizeof(POINT));

		BITMAPINFOHEADER BitMapHead;
		BitMapHead.biSize=sizeof(BITMAPINFOHEADER);
		BitMapHead.biWidth=m_rc.right-m_rc.left;
		BitMapHead.biHeight=m_rc.bottom-m_rc.top;
		BitMapHead.biPlanes=1;
		BitMapHead.biBitCount=32;
		BitMapHead.biCompression=BI_RGB;
		BitMapHead.biSizeImage=0;
		BitMapHead.biXPelsPerMeter=0;
		BitMapHead.biYPelsPerMeter=0;
		BitMapHead.biClrUsed=0;
		BitMapHead.biClrImportant=0;

		DWORD  Length=8*BitMapHead.biWidth*BitMapHead.biHeight;
		char BitMapFileName[20];
		_snprintf(BitMapFileName,sizeof(BitMapFileName),".%x.bc",this);
		HANDLE hFile=CreateFile(BitMapFileName,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_FLAG_DELETE_ON_CLOSE,NULL);
		HANDLE hMap=CreateFileMapping(hFile,0,PAGE_READWRITE,0,Length,0);
		//CloseHandle(hFile);
		VOID *ppvBits;
		if(m_MemBitMap.CreateDIBSection(m_OriginalHDC,(BITMAPINFO*)&BitMapHead,DIB_RGB_COLORS,&ppvBits,hMap,0))
		{
			m_OrigMemBitMap=SelectBitmap(m_MemBitMap);
			FillSolidRect(&m_rc,GetSysColor(COLOR_WINDOW));
			::DPtoLP(m_OriginalHDC,(LPPOINT) &m_rc,sizeof(RECT)/sizeof(POINT));
			SetWindowOrg(m_rc.left,m_rc.top);
		}else
		{
			if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: Failed in CreateDIBitmap(%d,%d)\n",__FUNCTION__,
				BitMapHead.biWidth,
				BitMapHead.biHeight);
		}
	}
	~CMemDC()
	{
		DeleteDC();
	}
};

class CGraphVizWindow : public CScrollWindowImpl<CGraphVizWindow>
{
private:
	int DebugLevel;
public:
	BOOL PreTranslateMessage(MSG* pMsg){
		return FALSE;
	}

 	void SetCallbackHandler(int (*paramCallbackHandler)(DWORD data,DWORD CallbackArgument1,DWORD CallbackArgument2,int offset_x,int offset_y),
		DWORD paramCallbackArgument1=0,DWORD paramCallbackArgument2=0
	)
	{
		CallbackHandler=paramCallbackHandler;
		CallbackArgument1=paramCallbackArgument1;
		CallbackArgument2=paramCallbackArgument2;
	}

private:
	float m_ZoomLevel;
	int m_ClientWidth;
	int m_ClientHeight;
	CMemDC *MemDC;
	int xWinOrg;
	int yWinOrg;
	int (*CallbackHandler)(DWORD data,DWORD CallbackArgument1,DWORD CallbackArgument2,int offset_x,int offset_y);
	DWORD CallbackArgument1;
	DWORD CallbackArgument2;

	BEGIN_MSG_MAP_EX(CGraphVizWindow)
		MSG_WM_CREATE(OnCreate)
		MESSAGE_HANDLER(WM_LBUTTONDOWN,OnLButtonDown)
		CHAIN_MSG_MAP(CScrollWindowImpl<CGraphVizWindow>)
		CHAIN_MSG_MAP_ALT(CScrollWindowImpl<CGraphVizWindow>,1)
	END_MSG_MAP()

	list<DrawingInfo *> *DrawingInfoMap;
	LRESULT OnCreate(LPCREATESTRUCT lpcs)
	{
		DebugLevel=0;
		LRESULT lRet=DefWindowProc();
		SetScrollSize(800,600);
		SetScrollLine(20,20);
		SetScrollPage(40,40);
		SetMsgHandled(false);
		DrawingInfoMap=NULL;
		xWinOrg=0;
		yWinOrg=0;
		MemDC=NULL;
		m_ClientWidth=0;
		m_ClientHeight=0;
		CallbackHandler=NULL;
		m_ZoomLevel=1;
		return lRet;
	}

	~CGraphVizWindow()
	{
		if(MemDC)
			delete MemDC;
	}

	LRESULT OnLButtonDown(UINT uMsg,WPARAM wParam,LPARAM lParam,BOOL& bHandled)
	{
		SetFocus();
		POINT ScrollOffset;
		GetScrollOffset(ScrollOffset);
		int x=(int)((float)(MAKEPOINTS(lParam).x+ScrollOffset.x)/(float)m_ZoomLevel);
		int y=(int)((float)(MAKEPOINTS(lParam).y+ScrollOffset.y)/(float)m_ZoomLevel);
		if(!DrawingInfoMap)
			return 0;
		DWORD address=0;
		list<DrawingInfo *>::iterator DrawingInfoMapIterator;

		int offset_x=0;
		int offset_y=0;
		for(DrawingInfoMapIterator=DrawingInfoMap->begin();
			DrawingInfoMapIterator!=DrawingInfoMap->end();
			DrawingInfoMapIterator++)
		{
			DrawingInfo *p_drawing_info=*DrawingInfoMapIterator;

			if(p_drawing_info->type==TYPE_DI_RECTS)
			{
				if(p_drawing_info->points && p_drawing_info->count>0)
				{
					int pos;
					int min_x=0;
					int min_y=0;
					int max_x=0;
					int max_y=0;
					for(pos=0;pos<p_drawing_info->count;pos+=1)
					{
						if(min_x==0)
							min_x=p_drawing_info->points[pos].x;
						else
							min_x=min(min_x,p_drawing_info->points[pos].x);
						if(min_y==0)
							min_y=p_drawing_info->points[pos].y;
						else
							min_y=min(min_y,p_drawing_info->points[pos].y);
						if(max_x==0)
							max_x=p_drawing_info->points[pos].x;
						else
							max_x=max(max_x,p_drawing_info->points[pos].x);
						if(max_y==0)
							max_y=p_drawing_info->points[pos].y;
						else
							max_y=max(max_y,p_drawing_info->points[pos].y);
					}

					if(min_x<=x && x<=max_x &&
					min_y<=y && y<=max_y)
					{
						address=p_drawing_info->address;
						if(offset_x>0)
							offset_x=min(offset_x,min_x);
						else
							offset_x=min_x;
						if(offset_y>0)
							offset_y=min(offset_y,min_y);
						else
							offset_y=min_y;
					
					}
				}
			}
		}
		if(address>0 && CallbackHandler)
		{
			CallbackHandler(address,
				CallbackArgument1,
				CallbackArgument2,
				(int)(offset_x*m_ZoomLevel-ScrollOffset.x),
				(int)(offset_y*m_ZoomLevel-ScrollOffset.y));
		}
		return 1;
	}

	LRESULT ShowNode(DWORD address,DWORD offset_x=0,DWORD offset_y=0)
	{
		if(!DrawingInfoMap)
			return 0;
		int min_x=-1;
		int min_y=-1;
		list<DrawingInfo *>::iterator DrawingInfoMapIterator;
		for(DrawingInfoMapIterator=DrawingInfoMap->begin();
			DrawingInfoMapIterator!=DrawingInfoMap->end();
			DrawingInfoMapIterator++)
		{
			DrawingInfo *p_drawing_info=*DrawingInfoMapIterator;
			if(address==p_drawing_info->address && p_drawing_info->type==TYPE_DI_RECTS)
			{
				if(p_drawing_info->points && p_drawing_info->count>0)
				{
					int pos;
					for(pos=0;pos<p_drawing_info->count;pos+=1)
					{
						if(min_x>0)
							min_x=min(min_x,p_drawing_info->points[pos].x);
						else
							min_x=p_drawing_info->points[pos].x;
						if(min_y>0)
							min_y=min(min_y,p_drawing_info->points[pos].y);
						else
							min_y=p_drawing_info->points[pos].y;
					}
				}
			}
		}
		if(min_x>=0 && min_y>=0)
		{
			POINT ScrollOffset;
			ScrollOffset.x=(int)(min_x*m_ZoomLevel)-offset_x;
			ScrollOffset.y=(int)(min_y*m_ZoomLevel)-offset_y;
			SetScrollOffset(ScrollOffset);
		}
		return 1;
	}

	void SetWindowSize(int ClientWidth,int ClientHeight)
	{
		RECT ClientRect;
		RECT WindowRect;
		int WindowWidth,WindowHeight;
		::GetClientRect(GetActiveWindow(),&ClientRect);
		::GetWindowRect(GetActiveWindow(),&WindowRect);
		WindowWidth=ClientWidth+
				(WindowRect.right-WindowRect.left) -
				(ClientRect.right-ClientRect.left);
		WindowHeight=ClientHeight+
				(WindowRect.bottom-WindowRect.top) -
				(ClientRect.bottom-ClientRect.top);
		::SetWindowPos(GetActiveWindow(),NULL,0,0,
				WindowWidth,WindowHeight,SWP_NOMOVE|SWP_NOZORDER);
	}

	void SetDrawingInfoMap(list<DrawingInfo *> *DrawingInfoMapParam)
	{
		if(DrawingInfoMap)
		{
			list<DrawingInfo *>::iterator DrawingInfoMapIterator;
			for(DrawingInfoMapIterator=DrawingInfoMap->begin();
				DrawingInfoMapIterator!=DrawingInfoMap->end();
				DrawingInfoMapIterator++)
			{
				DrawingInfo *p_drawing_info=*DrawingInfoMapIterator;
				if(p_drawing_info->points)
					free(p_drawing_info->points);
				if(p_drawing_info->text)
					free(p_drawing_info->text);
				free(p_drawing_info);
			}
			delete DrawingInfoMap;
		}
		DrawingInfoMap=DrawingInfoMapParam;
		if(!DrawingInfoMap)
			return;
		m_ClientWidth=0;
		m_ClientHeight=0;
		list<DrawingInfo *>::iterator DrawingInfoMapIterator;

		for(DrawingInfoMapIterator=DrawingInfoMap->begin();
			DrawingInfoMapIterator!=DrawingInfoMap->end();
			DrawingInfoMapIterator++)
		{
			DrawingInfo *p_drawing_info=*DrawingInfoMapIterator;
			if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: p_drawing_info=%x\n",__FUNCTION__,p_drawing_info);
			if(p_drawing_info->type==TYPE_DI_GRAPH)
			{
				xWinOrg=p_drawing_info->points[1].x;
				yWinOrg=p_drawing_info->points[1].y;
				m_ClientWidth=p_drawing_info->points[1].x+10;
				m_ClientHeight=p_drawing_info->points[1].y+10;
				if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: m_ClientWidth: %d m_ClientHeight:%d\n",__FUNCTION__,m_ClientWidth,m_ClientHeight);
				SetScrollSize((int)((float)m_ClientWidth*m_ZoomLevel)+1,(int)((float)m_ClientHeight*m_ZoomLevel)+1);
			}
		}
		for(DrawingInfoMapIterator=DrawingInfoMap->begin();
			DrawingInfoMapIterator!=DrawingInfoMap->end();
			DrawingInfoMapIterator++)
		{
			DrawingInfo *p_drawing_info=*DrawingInfoMapIterator;
			int pos;
			for(pos=0;pos<p_drawing_info->count;pos+=1)
			{
				if(p_drawing_info->type==TYPE_DI_DRAW && p_drawing_info->subtype=='T' && pos==1)
				{
				}else
				{
					p_drawing_info->points[pos].y=yWinOrg-p_drawing_info->points[pos].y;
				}
			}
		}
		if(MemDC)
		{
			delete MemDC;
			MemDC=NULL;
		}
	}

	void SetZoomLevel(float ZoomLevel)
	{
		float PreviousZoomLevel=m_ZoomLevel;
		m_ZoomLevel=ZoomLevel;

		POINT ScrollOffset;
		GetScrollOffset(ScrollOffset);
		RECT rc;
		GetClientRect(&rc);
		int ClientWidth=rc.right-rc.left;
		int ClientHeight=rc.bottom-rc.top;

		ScrollOffset.x=(int)((float)(ScrollOffset.x+ClientWidth/2)*(m_ZoomLevel/PreviousZoomLevel)-ClientWidth/2);
		if(ScrollOffset.x<0)
			ScrollOffset.x=0;

		ScrollOffset.y=(int)((float)(ScrollOffset.y+ClientHeight/2)*(m_ZoomLevel/PreviousZoomLevel)-ClientHeight/2);
		if(ScrollOffset.y<0)
			ScrollOffset.y=0;

		int ScrollSizeX=(int)((float)m_ClientWidth*m_ZoomLevel);
		int ScrollSizeY=(int)((float)m_ClientHeight*m_ZoomLevel);
		if(ScrollSizeX>0 && ScrollSizeY>0)
		{
			SetScrollSize(ScrollSizeX,ScrollSizeY);
		}
		if(ScrollOffset.x>0 && ScrollOffset.y>0)
		{
			SetScrollOffset(ScrollOffset);
		}
	}

	COLORREF GetColorFromName(char *name)
	{
		typedef struct
		{
			char *name;
			DWORD color;
		}Colors;
		static Colors AllColors[]=
		{
			{"aliceblue",0xf0f8ff},
			{"antiquewhite",0xfaebd7},
			{"antiquewhite1",0xffefdb},
			{"antiquewhite2",0xeedfcc},
			{"antiquewhite3",0xcdc0b0},
			{"antiquewhite4",0x8b8378},
			{"aquamarine",0x7fffd4},
			{"aquamarine1",0x7fffd4},
			{"aquamarine2",0x76eec6},
			{"aquamarine3",0x66cdaa},
			{"aquamarine4",0x458b74},
			{"azure",0xf0ffff},
			{"azure1",0xf0ffff},
			{"azure2",0xe0eeee},
			{"azure3",0xc1cdcd},
			{"azure4",0x838b8b},
			{"beige",0xf5f5dc},
			{"bisque",0xffe4c4},
			{"bisque1",0xffe4c4},
			{"bisque2",0xeed5b7},
			{"bisque3",0xcdb79e},
			{"bisque4",0x8b7d6b},
			{"black",0x000000},
			{"blanchedalmond",0xffebcd},
			{"blue",0x0000ff},
			{"blue1",0x0000ff},
			{"blue2",0x0000ee},
			{"blue3",0x0000cd},
			{"blue4",0x00008b},
			{"blueviolet",0x8a2be2},
			{"brown",0xa52a2a},
			{"brown1",0xff4040},
			{"brown2",0xee3b3b},
			{"brown3",0xcd3333},
			{"brown4",0x8b2323},
			{"burlywood",0xdeb887},
			{"burlywood1",0xffd39b},
			{"burlywood2",0xeec591},
			{"burlywood3",0xcdaa7d},
			{"burlywood4",0x8b7355},
			{"cadetblue",0x5f9ea0},
			{"cadetblue1",0x98f5ff},
			{"cadetblue2",0x8ee5ee},
			{"cadetblue3",0x7ac5cd},
			{"cadetblue4",0x53868b},
			{"chartreuse",0x7fff00},
			{"chartreuse1",0x7fff00},
			{"chartreuse2",0x76ee00},
			{"chartreuse3",0x66cd00},
			{"chartreuse4",0x458b00},
			{"chocolate",0xd2691e},
			{"chocolate1",0xff7f24},
			{"chocolate2",0xee7621},
			{"chocolate3",0xcd661d},
			{"chocolate4",0x8b4513},
			{"coral",0xff7f50},
			{"coral1",0xff7256},
			{"coral2",0xee6a50},
			{"coral3",0xcd5b45},
			{"coral4",0x8b3e2f},
			{"cornflowerblue",0x6495ed},
			{"cornsilk",0xfff8dc},
			{"cornsilk1",0xfff8dc},
			{"cornsilk2",0xeee8cd},
			{"cornsilk3",0xcdc8b1},
			{"cornsilk4",0x8b8878},
			{"crimson",0xdc143c},
			{"cyan",0x00ffff},
			{"cyan1",0x00ffff},
			{"cyan2",0x00eeee},
			{"cyan3",0x00cdcd},
			{"cyan4",0x008b8b},
			{"darkgoldenrod",0xb8860b},
			{"darkgoldenrod1",0xffb90f},
			{"darkgoldenrod2",0xeead0e},
			{"darkgoldenrod3",0xcd950c},
			{"darkgoldenrod4",0x8b6508},
			{"darkgreen",0x006400},
			{"darkkhaki",0xbdb76b},
			{"darkolivegreen",0x556b2f},
			{"darkolivegreen1",0xcaff70},
			{"darkolivegreen2",0xbcee68},
			{"darkolivegreen3",0xa2cd5a},
			{"darkolivegreen4",0x6e8b3d},
			{"darkorange",0xff8c00},
			{"darkorange1",0xff7f00},
			{"darkorange2",0xee7600},
			{"darkorange3",0xcd6600},
			{"darkorange4",0x8b4500},
			{"darkorchid",0x9932cc},
			{"darkorchid1",0xbf3eff},
			{"darkorchid2",0xb23aee},
			{"darkorchid3",0x9a32cd},
			{"darkorchid4",0x68228b},
			{"darksalmon",0xe9967a},
			{"darkseagreen",0x8fbc8f},
			{"darkseagreen1",0xc1ffc1},
			{"darkseagreen2",0xb4eeb4},
			{"darkseagreen3",0x9bcd9b},
			{"darkseagreen4",0x698b69},
			{"darkslateblue",0x483d8b},
			{"darkslategray",0x2f4f4f},
			{"darkslategray1",0x97ffff},
			{"darkslategray2",0x8deeee},
			{"darkslategray3",0x79cdcd},
			{"darkslategray4",0x528b8b},
			{"darkslategrey",0x2f4f4f},
			{"darkturquoise",0x00ced1},
			{"darkviolet",0x9400d3},
			{"deeppink",0xff1493},
			{"deeppink1",0xff1493},
			{"deeppink2",0xee1289},
			{"deeppink3",0xcd1076},
			{"deeppink4",0x8b0a50},
			{"deepskyblue",0x00bfff},
			{"deepskyblue1",0x00bfff},
			{"deepskyblue2",0x00b2ee},
			{"deepskyblue3",0x009acd},
			{"deepskyblue4",0x00688b},
			{"dimgray",0x696969},
			{"dimgrey",0x696969},
			{"dodgerblue",0x1e90ff},
			{"dodgerblue1",0x1e90ff},
			{"dodgerblue2",0x1c86ee},
			{"dodgerblue3",0x1874cd},
			{"dodgerblue4",0x104e8b},
			{"firebrick",0xb22222},
			{"firebrick1",0xff3030},
			{"firebrick2",0xee2c2c},
			{"firebrick3",0xcd2626},
			{"firebrick4",0x8b1a1a},
			{"floralwhite",0xfffaf0},
			{"forestgreen",0x228b22},
			{"gainsboro",0xdcdcdc},
			{"ghostwhite",0xf8f8ff},
			{"gold",0xffd700},
			{"gold1",0xffd700},
			{"gold2",0xeec900},
			{"gold3",0xcdad00},
			{"gold4",0x8b7500},
			{"goldenrod",0xdaa520},
			{"goldenrod1",0xffc125},
			{"goldenrod2",0xeeb422},
			{"goldenrod3",0xcd9b1d},
			{"goldenrod4",0x8b6914},
			{"gray",0xc0c0c0},
			{"gray0",0x000000},
			{"gray1",0x030303},
			{"gray2",0x050505},
			{"gray3",0x080808},
			{"gray4",0x0a0a0a},
			{"gray5",0x0d0d0d},
			{"gray6",0x0f0f0f},
			{"gray7",0x121212},
			{"gray8",0x141414},
			{"gray9",0x171717},
			{"gray10",0x1a1a1a},
			{"gray11",0x1c1c1c},
			{"gray12",0x1f1f1f},
			{"gray13",0x212121},
			{"gray14",0x242424},
			{"gray15",0x262626},
			{"gray16",0x292929},
			{"gray17",0x2b2b2b},
			{"gray18",0x2e2e2e},
			{"gray19",0x303030},
			{"gray20",0x333333},
			{"gray21",0x363636},
			{"gray22",0x383838},
			{"gray23",0x3b3b3b},
			{"gray24",0x3d3d3d},
			{"gray25",0x404040},
			{"gray26",0x424242},
			{"gray27",0x454545},
			{"gray28",0x474747},
			{"gray29",0x4a4a4a},
			{"gray30",0x4d4d4d},
			{"gray31",0x4f4f4f},
			{"gray32",0x525252},
			{"gray33",0x545454},
			{"gray34",0x575757},
			{"gray35",0x595959},
			{"gray36",0x5c5c5c},
			{"gray37",0x5e5e5e},
			{"gray38",0x616161},
			{"gray39",0x636363},
			{"gray40",0x666666},
			{"gray41",0x696969},
			{"gray42",0x6b6b6b},
			{"gray43",0x6e6e6e},
			{"gray44",0x707070},
			{"gray45",0x737373},
			{"gray46",0x757575},
			{"gray47",0x787878},
			{"gray48",0x7a7a7a},
			{"gray49",0x7d7d7d},
			{"gray50",0x7f7f7f},
			{"gray51",0x828282},
			{"gray52",0x858585},
			{"gray53",0x878787},
			{"gray54",0x8a8a8a},
			{"gray55",0x8c8c8c},
			{"gray56",0x8f8f8f},
			{"gray57",0x919191},
			{"gray58",0x949494},
			{"gray59",0x969696},
			{"gray60",0x999999},
			{"gray61",0x9c9c9c},
			{"gray62",0x9e9e9e},
			{"gray63",0xa1a1a1},
			{"gray64",0xa3a3a3},
			{"gray65",0xa6a6a6},
			{"gray66",0xa8a8a8},
			{"gray67",0xababab},
			{"gray68",0xadadad},
			{"gray69",0xb0b0b0},
			{"gray70",0xb3b3b3},
			{"gray71",0xb5b5b5},
			{"gray72",0xb8b8b8},
			{"gray73",0xbababa},
			{"gray74",0xbdbdbd},
			{"gray75",0xbfbfbf},
			{"gray76",0xc2c2c2},
			{"gray77",0xc4c4c4},
			{"gray78",0xc7c7c7},
			{"gray79",0xc9c9c9},
			{"gray80",0xcccccc},
			{"gray81",0xcfcfcf},
			{"gray82",0xd1d1d1},
			{"gray83",0xd4d4d4},
			{"gray84",0xd6d6d6},
			{"gray85",0xd9d9d9},
			{"gray86",0xdbdbdb},
			{"gray87",0xdedede},
			{"gray88",0xe0e0e0},
			{"gray89",0xe3e3e3},
			{"gray90",0xe5e5e5},
			{"gray91",0xe8e8e8},
			{"gray92",0xebebeb},
			{"gray93",0xededed},
			{"gray94",0xf0f0f0},
			{"gray95",0xf2f2f2},
			{"gray96",0xf5f5f5},
			{"gray97",0xf7f7f7},
			{"gray98",0xfafafa},
			{"gray99",0xfcfcfc},
			{"gray100",0xffffff},
			{"green",0x00ff00},
			{"green1",0x00ff00},
			{"green2",0x00ee00},
			{"green3",0x00cd00},
			{"green4",0x008b00},
			{"greenyellow",0xadff2f},
			{"grey",0xc0c0c0},
			{"grey0",0x000000},
			{"grey1",0x030303},
			{"grey2",0x050505},
			{"grey3",0x080808},
			{"grey4",0x0a0a0a},
			{"grey5",0x0d0d0d},
			{"grey6",0x0f0f0f},
			{"grey7",0x121212},
			{"grey8",0x141414},
			{"grey9",0x171717},
			{"grey10",0x1a1a1a},
			{"grey11",0x1c1c1c},
			{"grey12",0x1f1f1f},
			{"grey13",0x212121},
			{"grey14",0x242424},
			{"grey15",0x262626},
			{"grey16",0x292929},
			{"grey17",0x2b2b2b},
			{"grey18",0x2e2e2e},
			{"grey19",0x303030},
			{"grey20",0x333333},
			{"grey21",0x363636},
			{"grey22",0x383838},
			{"grey23",0x3b3b3b},
			{"grey24",0x3d3d3d},
			{"grey25",0x404040},
			{"grey26",0x424242},
			{"grey27",0x454545},
			{"grey28",0x474747},
			{"grey29",0x4a4a4a},
			{"grey30",0x4d4d4d},
			{"grey31",0x4f4f4f},
			{"grey32",0x525252},
			{"grey33",0x545454},
			{"grey34",0x575757},
			{"grey35",0x595959},
			{"grey36",0x5c5c5c},
			{"grey37",0x5e5e5e},
			{"grey38",0x616161},
			{"grey39",0x636363},
			{"grey40",0x666666},
			{"grey41",0x696969},
			{"grey42",0x6b6b6b},
			{"grey43",0x6e6e6e},
			{"grey44",0x707070},
			{"grey45",0x737373},
			{"grey46",0x757575},
			{"grey47",0x787878},
			{"grey48",0x7a7a7a},
			{"grey49",0x7d7d7d},
			{"grey50",0x7f7f7f},
			{"grey51",0x828282},
			{"grey52",0x858585},
			{"grey53",0x878787},
			{"grey54",0x8a8a8a},
			{"grey55",0x8c8c8c},
			{"grey56",0x8f8f8f},
			{"grey57",0x919191},
			{"grey58",0x949494},
			{"grey59",0x969696},
			{"grey60",0x999999},
			{"grey61",0x9c9c9c},
			{"grey62",0x9e9e9e},
			{"grey63",0xa1a1a1},
			{"grey64",0xa3a3a3},
			{"grey65",0xa6a6a6},
			{"grey66",0xa8a8a8},
			{"grey67",0xababab},
			{"grey68",0xadadad},
			{"grey69",0xb0b0b0},
			{"grey70",0xb3b3b3},
			{"grey71",0xb5b5b5},
			{"grey72",0xb8b8b8},
			{"grey73",0xbababa},
			{"grey74",0xbdbdbd},
			{"grey75",0xbfbfbf},
			{"grey76",0xc2c2c2},
			{"grey77",0xc4c4c4},
			{"grey78",0xc7c7c7},
			{"grey79",0xc9c9c9},
			{"grey80",0xcccccc},
			{"grey81",0xcfcfcf},
			{"grey82",0xd1d1d1},
			{"grey83",0xd4d4d4},
			{"grey84",0xd6d6d6},
			{"grey85",0xd9d9d9},
			{"grey86",0xdbdbdb},
			{"grey87",0xdedede},
			{"grey88",0xe0e0e0},
			{"grey89",0xe3e3e3},
			{"grey90",0xe5e5e5},
			{"grey91",0xe8e8e8},
			{"grey92",0xebebeb},
			{"grey93",0xededed},
			{"grey94",0xf0f0f0},
			{"grey95",0xf2f2f2},
			{"grey96",0xf5f5f5},
			{"grey97",0xf7f7f7},
			{"grey98",0xfafafa},
			{"grey99",0xfcfcfc},
			{"grey100",0xffffff},
			{"honeydew",0xf0fff0},
			{"honeydew1",0xf0fff0},
			{"honeydew2",0xe0eee0},
			{"honeydew3",0xc1cdc1},
			{"honeydew4",0x838b83},
			{"hotpink",0xff69b4},
			{"hotpink1",0xff6eb4},
			{"hotpink2",0xee6aa7},
			{"hotpink3",0xcd6090},
			{"hotpink4",0x8b3a62},
			{"indianred",0xcd5c5c},
			{"indianred1",0xff6a6a},
			{"indianred2",0xee6363},
			{"indianred3",0xcd5555},
			{"indianred4",0x8b3a3a},
			{"indigo",0x4b0082},
			{"ivory",0xfffff0},
			{"ivory1",0xfffff0},
			{"ivory2",0xeeeee0},
			{"ivory3",0xcdcdc1},
			{"ivory4",0x8b8b83},
			{"khaki",0xf0e68c},
			{"khaki1",0xfff68f},
			{"khaki2",0xeee685},
			{"khaki3",0xcdc673},
			{"khaki4",0x8b864e},
			{"lavender",0xe6e6fa},
			{"lavenderblush",0xfff0f5},
			{"lavenderblush1",0xfff0f5},
			{"lavenderblush2",0xeee0e5},
			{"lavenderblush3",0xcdc1c5},
			{"lavenderblush4",0x8b8386},
			{"lawngreen",0x7cfc00},
			{"lemonchiffon",0xfffacd},
			{"lemonchiffon1",0xfffacd},
			{"lemonchiffon2",0xeee9bf},
			{"lemonchiffon3",0xcdc9a5},
			{"lemonchiffon4",0x8b8970},
			{"lightblue",0xadd8e6},
			{"lightblue1",0xbfefff},
			{"lightblue2",0xb2dfee},
			{"lightblue3",0x9ac0cd},
			{"lightblue4",0x68838b},
			{"lightcoral",0xf08080},
			{"lightcyan",0xe0ffff},
			{"lightcyan1",0xe0ffff},
			{"lightcyan2",0xd1eeee},
			{"lightcyan3",0xb4cdcd},
			{"lightcyan4",0x7a8b8b},
			{"lightgoldenrod",0xeedd82},
			{"lightgoldenrod1",0xffec8b},
			{"lightgoldenrod2",0xeedc82},
			{"lightgoldenrod3",0xcdbe70},
			{"lightgoldenrod4",0x8b814c},
			{"lightgoldenrodyellow",0xfafad2},
			{"lightgray",0xd3d3d3},
			{"lightgrey",0xd3d3d3},
			{"lightpink",0xffb6c1},
			{"lightpink1",0xffaeb9},
			{"lightpink2",0xeea2ad},
			{"lightpink3",0xcd8c95},
			{"lightpink4",0x8b5f65},
			{"lightsalmon",0xffa07a},
			{"lightsalmon1",0xffa07a},
			{"lightsalmon2",0xee9572},
			{"lightsalmon3",0xcd8162},
			{"lightsalmon4",0x8b5742},
			{"lightseagreen",0x20b2aa},
			{"lightskyblue",0x87cefa},
			{"lightskyblue1",0xb0e2ff},
			{"lightskyblue2",0xa4d3ee},
			{"lightskyblue3",0x8db6cd},
			{"lightskyblue4",0x607b8b},
			{"lightslateblue",0x8470ff},
			{"lightslategray",0x778899},
			{"lightslategrey",0x778899},
			{"lightsteelblue",0xb0c4de},
			{"lightsteelblue1",0xcae1ff},
			{"lightsteelblue2",0xbcd2ee},
			{"lightsteelblue3",0xa2b5cd},
			{"lightsteelblue4",0x6e7b8b},
			{"lightyellow",0xffffe0},
			{"lightyellow1",0xffffe0},
			{"lightyellow2",0xeeeed1},
			{"lightyellow3",0xcdcdb4},
			{"lightyellow4",0x8b8b7a},
			{"limegreen",0x32cd32},
			{"linen",0xfaf0e6},
			{"magenta",0xff00ff},
			{"magenta1",0xff00ff},
			{"magenta2",0xee00ee},
			{"magenta3",0xcd00cd},
			{"magenta4",0x8b008b},
			{"maroon",0xb03060},
			{"maroon1",0xff34b3},
			{"maroon2",0xee30a7},
			{"maroon3",0xcd2990},
			{"maroon4",0x8b1c62},
			{"mediumaquamarine",0x66cdaa},
			{"mediumblue",0x0000cd},
			{"mediumorchid",0xba55d3},
			{"mediumorchid1",0xe066ff},
			{"mediumorchid2",0xd15fee},
			{"mediumorchid3",0xb452cd},
			{"mediumorchid4",0x7a378b},
			{"mediumpurple",0x9370db},
			{"mediumpurple1",0xab82ff},
			{"mediumpurple2",0x9f79ee},
			{"mediumpurple3",0x8968cd},
			{"mediumpurple4",0x5d478b},
			{"mediumseagreen",0x3cb371},
			{"mediumslateblue",0x7b68ee},
			{"mediumspringgreen",0x00fa9a},
			{"mediumturquoise",0x48d1cc},
			{"mediumvioletred",0xc71585},
			{"midnightblue",0x191970},
			{"mintcream",0xf5fffa},
			{"mistyrose",0xffe4e1},
			{"mistyrose1",0xffe4e1},
			{"mistyrose2",0xeed5d2},
			{"mistyrose3",0xcdb7b5},
			{"mistyrose4",0x8b7d7b},
			{"moccasin",0xffe4b5},
			{"navajowhite",0xffdead},
			{"navajowhite1",0xffdead},
			{"navajowhite2",0xeecfa1},
			{"navajowhite3",0xcdb38b},
			{"navajowhite4",0x8b795e},
			{"navy",0x000080},
			{"navyblue",0x000080},
			{"oldlace",0xfdf5e6},
			{"olivedrab",0x6b8e23},
			{"olivedrab1",0xc0ff3e},
			{"olivedrab2",0xb3ee3a},
			{"olivedrab3",0x9acd32},
			{"olivedrab4",0x698b22},
			{"orange",0xffa500},
			{"orange1",0xffa500},
			{"orange2",0xee9a00},
			{"orange3",0xcd8500},
			{"orange4",0x8b5a00},
			{"orangered",0xff4500},
			{"orangered1",0xff4500},
			{"orangered2",0xee4000},
			{"orangered3",0xcd3700},
			{"orangered4",0x8b2500},
			{"orchid",0xda70d6},
			{"orchid1",0xff83fa},
			{"orchid2",0xee7ae9},
			{"orchid3",0xcd69c9},
			{"orchid4",0x8b4789},
			{"palegoldenrod",0xeee8aa},
			{"palegreen",0x98fb98},
			{"palegreen1",0x9aff9a},
			{"palegreen2",0x90ee90},
			{"palegreen3",0x7ccd7c},
			{"palegreen4",0x548b54},
			{"paleturquoise",0xafeeee},
			{"paleturquoise1",0xbbffff},
			{"paleturquoise2",0xaeeeee},
			{"paleturquoise3",0x96cdcd},
			{"paleturquoise4",0x668b8b},
			{"palevioletred",0xdb7093},
			{"palevioletred1",0xff82ab},
			{"palevioletred2",0xee799f},
			{"palevioletred3",0xcd6889},
			{"palevioletred4",0x8b475d},
			{"papayawhip",0xffefd5},
			{"peachpuff",0xffdab9},
			{"peachpuff1",0xffdab9},
			{"peachpuff2",0xeecbad},
			{"peachpuff3",0xcdaf95},
			{"peachpuff4",0x8b7765},
			{"peru",0xcd853f},
			{"pink",0xffc0cb},
			{"pink1",0xffb5c5},
			{"pink2",0xeea9b8},
			{"pink3",0xcd919e},
			{"pink4",0x8b636c},
			{"plum",0xdda0dd},
			{"plum1",0xffbbff},
			{"plum2",0xeeaeee},
			{"plum3",0xcd96cd},
			{"plum4",0x8b668b},
			{"powderblue",0xb0e0e6},
			{"purple",0xa020f0},
			{"purple1",0x9b30ff},
			{"purple2",0x912cee},
			{"purple3",0x7d26cd},
			{"purple4",0x551a8b},
			{"red",0xff0000},
			{"red1",0xff0000},
			{"red2",0xee0000},
			{"red3",0xcd0000},
			{"red4",0x8b0000},
			{"rosybrown",0xbc8f8f},
			{"rosybrown1",0xffc1c1},
			{"rosybrown2",0xeeb4b4},
			{"rosybrown3",0xcd9b9b},
			{"rosybrown4",0x8b6969},
			{"royalblue",0x4169e1},
			{"royalblue1",0x4876ff},
			{"royalblue2",0x436eee},
			{"royalblue3",0x3a5fcd},
			{"royalblue4",0x27408b},
			{"saddlebrown",0x8b4513},
			{"salmon",0xfa8072},
			{"salmon1",0xff8c69},
			{"salmon2",0xee8262},
			{"salmon3",0xcd7054},
			{"salmon4",0x8b4c39},
			{"sandybrown",0xf4a460},
			{"seagreen",0x2e8b57},
			{"seagreen1",0x54ff9f},
			{"seagreen2",0x4eee94},
			{"seagreen3",0x43cd80},
			{"seagreen4",0x2e8b57},
			{"seashell",0xfff5ee},
			{"seashell1",0xfff5ee},
			{"seashell2",0xeee5de},
			{"seashell3",0xcdc5bf},
			{"seashell4",0x8b8682},
			{"sienna",0xa0522d},
			{"sienna1",0xff8247},
			{"sienna2",0xee7942},
			{"sienna3",0xcd6839},
			{"sienna4",0x8b4726},
			{"skyblue",0x87ceeb},
			{"skyblue1",0x87ceff},
			{"skyblue2",0x7ec0ee},
			{"skyblue3",0x6ca6cd},
			{"skyblue4",0x4a708b},
			{"slateblue",0x6a5acd},
			{"slateblue1",0x836fff},
			{"slateblue2",0x7a67ee},
			{"slateblue3",0x6959cd},
			{"slateblue4",0x473c8b},
			{"slategray",0x708090},
			{"slategray1",0xc6e2ff},
			{"slategray2",0xb9d3ee},
			{"slategray3",0x9fb6cd},
			{"slategray4",0x6c7b8b},
			{"slategrey",0x708090},
			{"snow",0xfffafa},
			{"snow1",0xfffafa},
			{"snow2",0xeee9e9},
			{"snow3",0xcdc9c9},
			{"snow4",0x8b8989},
			{"springgreen",0x00ff7f},
			{"springgreen1",0x00ff7f},
			{"springgreen2",0x00ee76},
			{"springgreen3",0x00cd66},
			{"springgreen4",0x008b45},
			{"steelblue",0x4682b4},
			{"steelblue1",0x63b8ff},
			{"steelblue2",0x5cacee},
			{"steelblue3",0x4f94cd},
			{"steelblue4",0x36648b},
			{"tan",0xd2b48c},
			{"tan1",0xffa54f},
			{"tan2",0xee9a49},
			{"tan3",0xcd853f},
			{"tan4",0x8b5a2b},
			{"thistle",0xd8bfd8},
			{"thistle1",0xffe1ff},
			{"thistle2",0xeed2ee},
			{"thistle3",0xcdb5cd},
			{"thistle4",0x8b7b8b},
			{"tomato",0xff6347},
			{"tomato1",0xff6347},
			{"tomato2",0xee5c42},
			{"tomato3",0xcd4f39},
			{"tomato4",0x8b3626},
			{"transparent",0xfffffe},
			{"turquoise",0x40e0d0},
			{"turquoise1",0x00f5ff},
			{"turquoise2",0x00e5ee},
			{"turquoise3",0x00c5cd},
			{"turquoise4",0x00868b},
			{"violet",0xee82ee},
			{"violetred",0xd02090},
			{"violetred1",0xff3e96},
			{"violetred2",0xee3a8c},
			{"violetred3",0xcd3278},
			{"violetred4",0x8b2252},
			{"wheat",0xf5deb3},
			{"wheat1",0xffe7ba},
			{"wheat2",0xeed8ae},
			{"wheat3",0xcdba96},
			{"wheat4",0x8b7e66},
			{"white",0xffffff},
			{"whitesmoke",0xf5f5f5},
			{"yellow",0xffff00},
			{"yellow1",0xffff00},
			{"yellow2",0xeeee00},
			{"yellow3",0xcdcd00},
			{"yellow4",0x8b8b00},
			{"yellowgreen",0x9acd32}
		};

		int EndPosition=sizeof(AllColors)/sizeof(AllColors[0]);
		int StartPosition=0;
		int CurrentPosition=0;
		int OldCurrentPosition=0;
		while(1)
		{
			printf("%d-%d\n",StartPosition,EndPosition);
			CurrentPosition=StartPosition+(EndPosition-StartPosition)/2;
			if(CurrentPosition==OldCurrentPosition)
				break;
			printf("Comparing with %s(%d):%s\n",AllColors[CurrentPosition].name,CurrentPosition,name);
			int ret=_stricmp(AllColors[CurrentPosition].name,name);
			if(ret>0)
			{
				EndPosition=CurrentPosition;
				//StartPosition=;
			}else if(ret==0)
			{
				//match
				if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: %s(%s)=RGB(%x,%x,%x)\n",__FUNCTION__,name,AllColors[CurrentPosition].name,
					(AllColors[CurrentPosition].color>>16)&0xff,
					(AllColors[CurrentPosition].color>>8)&0xff,
					AllColors[CurrentPosition].color&0xff
					);
				return RGB(
					(AllColors[CurrentPosition].color>>16)&0xff,
					(AllColors[CurrentPosition].color>>8)&0xff,
					AllColors[CurrentPosition].color&0xff
					);
			}else
			{
				StartPosition=CurrentPosition;
			}
		}
		if(name && name[0]=='#')
		{
			int TotalValue=0;
			for(DWORD i=1;i<strlen(name);i++)
			{
				char Char=name[i];
				int CurrentValue=0;
				if('a' <= Char && Char <='f')
				{
					CurrentValue=(Char-'a'+10);
				}else if('A' <= Char && Char <='F')
				{
					CurrentValue=(Char-'A'+10);
				}else if('0' <= Char && Char <='9')
				{
					CurrentValue=(Char-'0');
				}
				TotalValue=TotalValue*16+CurrentValue;
			}
			if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: %s=%x\n",__FUNCTION__,name,TotalValue);
			return RGB(
				(TotalValue>>16)&0xff,
				(TotalValue>>8)&0xff,
				TotalValue&0xff);
		}

		printf("%s: %s failed to lookup\n",__FUNCTION__,name);
		return RGB(0,0,0);
	}

	void DumpDrawingInfo(DrawingInfo *p_drawing_info)
	{
		static char *TypeDiDescriptions[]={
			"Rects",
			"Draw",
			"Graph",
			"Color",
			"FillColor"
		};

		//ParseXDOTAttributeString("c 5 -black F 14.000000 11 -Times-Roman T 1295 379 0 69 10 -0x77d529c8 c 5 -black F 14.000000 11 -Times-Roman T 1295 355 0 177 25 -_ObjectFromDIBResource@24 c 5 -black F 14.000000 11 -Times-Roman T 1295 331 0 250 41 -call _pfnLockResource; _LockResource(x,x)");
		//printf("Type: %s/%c\n",TypeDiDescriptions[p_drawing_info->type],p_drawing_info->type==TYPE_DI_DRAW?p_drawing_info->subtype:' ');
		//printf("\tcount=%d\n",p_drawing_info->count);
	}
	
	void DoPaintReal(CDCHandle dc)
	{
		if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: entry\n",__FUNCTION__);
		if(!DrawingInfoMap)
			return;
		//SetViewportOrgEx(dc,10,10,NULL);
		list<DrawingInfo *>::iterator DrawingInfoMapIterator;

		char *CurrentFontName="Helvetica";
		float CurrentFontSize=10.0;
		printf("%s\n",__FUNCTION__);

		char *FillColor=NULL;
		char *PenColor=NULL;
		char *BgColor=NULL;
		char *FontColor=NULL;
		for(DrawingInfoMapIterator=DrawingInfoMap->begin();
			DrawingInfoMapIterator!=DrawingInfoMap->end();
			DrawingInfoMapIterator++)
		{
			DrawingInfo *p_drawing_info=*DrawingInfoMapIterator;
			DWORD user_data=p_drawing_info->address;

			printf("%s: p_drawing_info=%p\n",__FUNCTION__,p_drawing_info);
			SetBkMode(dc,TRANSPARENT);

			DumpDrawingInfo(p_drawing_info);
			if(p_drawing_info->type==TYPE_DI_COLOR)
			{
				PenColor=p_drawing_info->text;
			}else if(p_drawing_info->type==TYPE_DI_FILLCOLOR)
			{
				FillColor=p_drawing_info->text;
				if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: [fillcolor] Got %s\n",__FUNCTION__,FillColor);
			}else if(p_drawing_info->type==TYPE_DI_BGCOLOR)
			{
				BgColor=p_drawing_info->text;
			}else if(p_drawing_info->type==TYPE_DI_FONTCOLOR)
			{
				FontColor=p_drawing_info->text;
				if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: [fontcolor] FontColor=%s\n",__FUNCTION__,FontColor);
			}else if(p_drawing_info->type==TYPE_DI_RECTS)
			{
				if(p_drawing_info->points && p_drawing_info->count>0)
				{
					HBRUSH hbrush=NULL;
					HBRUSH hbrushOld=NULL;
					if(BgColor)
					{
						if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: [BgColor] [%s]\n",__FUNCTION__,BgColor);
						hbrush=CreateSolidBrush(GetColorFromName(BgColor));
						hbrushOld=(HBRUSH)SelectObject(dc,hbrush); 
						BgColor=NULL;
					}
					HPEN hpen=NULL;
					HPEN hpenOld=NULL;
					if(PenColor)
					{
						hpen=CreatePen(PS_SOLID,1,GetColorFromName(PenColor));
						hpenOld=(HPEN)SelectObject(dc,hpen);
						PenColor=NULL;
					}
					Polygon(dc,p_drawing_info->points,p_drawing_info->count);
					if(hbrushOld)
					{
						SelectObject(dc,hbrushOld);
					}
					if(hbrush)
					{
						DeleteObject(hbrush);
					}
					if(hpenOld)
					{
						SelectObject(dc,hpenOld);
					}
					if(hpen)
					{
						DeleteObject(hpen);
					}
				}
			}else if(p_drawing_info->type==TYPE_DI_DRAW)
			{
				switch(p_drawing_info->subtype)
				{
					case 'E':
					{
						//E point_x point_y w h
						//Filled ellipse ((x-point_x)/w)2 + ((y-point_y)/h)2=1
						break;
					}
					case 'e':
					{
						//e point_x point_y w h
						//Unfilled ellipse ((x-point_x)/w)2 + ((y-point_y)/h)2=1 
						break;
					}
					case 'P':
					{
						//P n x1 y1 ... xn yn
						//Filled polygon using the given n points
						//filling
						HBRUSH hbrush=NULL;
						HBRUSH hbrushOld=NULL;
						if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: Polygon=%d points [fillcolor] FillColor=%s\n",__FUNCTION__,p_drawing_info->count,FillColor?FillColor:"");
						if(FillColor)
						{
							hbrush=CreateSolidBrush(GetColorFromName(FillColor));
							hbrushOld=(HBRUSH)SelectObject(dc,hbrush); 
							FillColor=NULL;
						}
						Polygon(dc,p_drawing_info->points,p_drawing_info->count);
						if(hbrushOld)
						{
							SelectObject(dc,hbrushOld);
						}
						if(hbrush)
						{
							DeleteObject(hbrush);
						}
						break;
					}
					case 'p':
					{
						//p n x1 y1 ... xn yn
						//Unfilled polygon using the given n points
						HPEN hpen=NULL;
						HPEN hpenOld=NULL;
						if(PenColor)
						{
							hpen=CreatePen(PS_SOLID,1,GetColorFromName(PenColor));
							hpenOld=(HPEN)SelectObject(dc,hpen);
							PenColor=NULL;
						}
						printf("%s: Polygon=%d points\n",__FUNCTION__,p_drawing_info->count);
						Polygon(dc,p_drawing_info->points,p_drawing_info->count);
						if(hpenOld)
						{
							SelectObject(dc,hpenOld);
						}
						if(hpen)
						{
							DeleteObject(hpen);
						}
						break;
					}
					case 'L':
					{
						//L n x1 y1 ... xn yn
						//Polyline using the given n points
						Polyline(dc,p_drawing_info->points,p_drawing_info->count);
						break;
					}
					case 'B':
					{
						//B n x1 y1 ... xn yn
						//B-spline using the given n control points
						//B-spline
						//p_drawing_info->count
						//p_drawing_info->points
						PolyBezier(dc,p_drawing_info->points,p_drawing_info->count);
						break;
					}
					case 'b':
					{
						//b n x1 y1 ... xn yn
						//Filled B-spline using the given n control points (1.1)
						PolyBezier(dc,p_drawing_info->points,p_drawing_info->count);
						break;
					}
					case 'T':
					{
						//T x y j w n -c1c2...cn
						//Text drawn using the baseline point (x,y). The text consists of the n characters following '-'. 
						//The text should be left-aligned (centered,right-aligned) on the point if j is -1 (0,1),
						//respectively. The value w gives the width of the text as computed by the library.
						//p_drawing_info->text
						//p_drawing_info->points[0].x,
						//p_drawing_info->points[0].y,
						//p_drawing_info->points[1].y,//j
						//p_drawing_info->points[1].x,
						//ex) T 43 114 0 29 4 -xxxx

						HPEN hpen=NULL;
						HPEN hpenOld=NULL;
						if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: [fontcolor] Using FontColor=%s for Text [%s]\n",__FUNCTION__,FontColor,p_drawing_info->text);
						//TODO: Calcuate accurate font size
						CFont CurrentFont;
						if(!CurrentFont.CreatePointFont((int)(CurrentFontSize*7),CurrentFontName))
							CurrentFont.CreatePointFont((int)(CurrentFontSize*7),"Arial");
						HFONT hOldFont=dc.SelectFont(CurrentFont);
						dc.SetTextColor(GetColorFromName(FontColor));
						if(p_drawing_info->points[1].y==-1)//left-aligned
						{
						}
						if(p_drawing_info->points[1].y==0)//centered
						{
							#define XWIDTH p_drawing_info->points[1].x
							#define YWIDTH (int)CurrentFontSize
							CRect rect=CRect(p_drawing_info->points[0].x-XWIDTH,p_drawing_info->points[0].y-YWIDTH,p_drawing_info->points[0].x+XWIDTH,p_drawing_info->points[0].y+YWIDTH);
							dc.DrawText(p_drawing_info->text,-1,rect,DT_VCENTER|DT_CENTER);
						}
						if(p_drawing_info->points[1].y==1)//right-aligned
						{
						}
						break;
					}
					case 'C':
					{
						//C n -c1c2...cn
						//Set fill color. The color value consists of the n characters following '-'. (1.1)
						FillColor=p_drawing_info->text;
						if(DebugLevel>0) if(DebugLevel>0) dprintf("%s: [fillcolor] Set %s\n",__FUNCTION__,FillColor);
						break;
					}
					case 'c':
					{
						//c n -c1c2...cn
						//Set pen color. The color value consists of the n characters following '-'. (1.1)
						PenColor=p_drawing_info->text;
						break;
					}
					case 'F':
					{
						//F s n -c1c2...cn
						//Set font. The font size is s points. The font name consists of the n characters following '-'. (1.1)
						//size
						//text
						//ex) F 14.000000						
						CurrentFontSize=p_drawing_info->size;
						CurrentFontName=p_drawing_info->text;
						break;
					}
					case 'S':
					{
						//S n -c1c2...cn
						//Set style attribute. The style value consists of the n characters following '-'. The syntax of the value is the same as specified for a styleItem in style. (1.1)  
						break;
					}
					case 'I':
					{
						//I x y w h n -c1c2...cn
						//Externally-specified image drawn in the box with lower left corner (x,y) and upper right corner (x+w,y+h). The name of the image consists of the n characters following '-'. This is usually a bitmap image. Note that the image size,even when converted from pixels to points,might be different from the required size (w,h). It is assumed the renderer will perform the necessary scaling. (1.2)
						break;
					}
				}
			}
		}
	}

	void DoPaint(CDCHandle dc)
	{
		if(!MemDC)
		{
			CSize size;
			GetScrollSize(size);
			RECT rc;
			rc.left=0;
			rc.right=m_ClientWidth;
			rc.top=0;
			rc.bottom=m_ClientHeight;
			MemDC=new CMemDC(dc.m_hDC,&rc);
			if(DebugLevel>0) if(DebugLevel>0) dprintf("%s(%x): Drawing on MemDC(%d,%d,%d,%d)\n",__FUNCTION__,this,rc.left,rc.top,rc.right-rc.left,rc.bottom-rc.top);
			DoPaintReal(CDCHandle(MemDC->m_hDC));
		}
		if(MemDC)
		{
			RECT rc;
			GetClientRect(&rc);
			rc.left+=m_ptOffset.x;
			rc.right+=m_ptOffset.x;
			rc.top+=m_ptOffset.y;
			rc.bottom+=m_ptOffset.y;

			if(DebugLevel>0) if(DebugLevel>0) dprintf("%s(%x): Copying to the Window(%d,%d,%d,%d)\n",__FUNCTION__,this,rc.left,rc.top,rc.right-rc.left,rc.bottom-rc.top);
			//dc.BitBlt(rc.left,rc.top,rc.right-rc.left,rc.bottom-rc.top,*MemDC,rc.left,rc.top,SRCCOPY);
			dc.StretchBlt(rc.left,rc.top,rc.right-rc.left,rc.bottom-rc.top,*MemDC,(int)((float)rc.left/m_ZoomLevel),(int)((float)rc.top/m_ZoomLevel),(int)((float)(rc.right-rc.left)/m_ZoomLevel),(int)((float)(rc.bottom-rc.top)/m_ZoomLevel),SRCCOPY);
			//rc.left,rc.top,rc.right-rc.left,rc.bottom-rc.top
		}
	}
};

