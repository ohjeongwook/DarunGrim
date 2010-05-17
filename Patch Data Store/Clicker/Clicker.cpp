#include <stdio.h>
#include "Implementation.h"

class WindowDataCollection
{
private:
	int Level;
public:

	WindowDataCollection(): Level( 0 )
	{
	}

	void IncreaseLevel()
	{
		Level++;
	}

	void DecreaseLevel()
	{
		Level--;
	}

	int GetLevel()
	{
		return Level;
	}

	void AddWindowHandle( HWND hwnd )
	{
		//Level, handle
		for( int i = 0; i < Level ; i++ )
		{
			printf( " " );
		}
		char Buffer[1024];
		GetWindowText( hwnd, Buffer, sizeof( Buffer ) );
		//printf("%x: %s\n", hwnd, Buffer );
		printf("[%s]\n", Buffer );

		if( Level == 1 )
			SetActiveWindow( hwnd );

		//TODO: Separate clicking thread from enumeration thread
		if( !strcmp( Buffer, "&Save" ) || !strcmp( Buffer, "&Yes" ) || !strcmp( Buffer, "Yes" )  || !strcmp( Buffer, "OK" )  || !strcmp( Buffer, "&OK" )  || !strcmp( Buffer, "Run" ))
		{
			printf("Sending Message to [%s]\n", Buffer );
			::SendMessage(hwnd, BM_SETSTATE, 1, 0 );
			printf("Clicked [%s]\n", Buffer );
			::SendMessage(hwnd, BM_CLICK, 0, 0 );
			printf("Click Returned [%s]\n", Buffer );
		}
	}
};

BOOL CALLBACK EnumWindowsProc(
  __in  HWND hwnd,
  __in  LPARAM lParam
)
{
	WindowDataCollection *pWindowDataCollection = (WindowDataCollection *)lParam;
	pWindowDataCollection->IncreaseLevel();
	pWindowDataCollection->AddWindowHandle( hwnd );

	BOOL ret = EnumChildWindows(
		hwnd,
		EnumWindowsProc,
		lParam
	);

	pWindowDataCollection->DecreaseLevel();
	return TRUE;
}

int main()
{
	//TODO: to do this in time interval
	WindowDataCollection *pWindowDataCollection = new WindowDataCollection();
	BOOL ret = EnumWindows( EnumWindowsProc, (LPARAM)  pWindowDataCollection );
}
