#include <stdio.h>
#include <string>
#include "Implementation.h"

class WindowDataCollection
{
private:
	int Level;
	std::string TopLevelText;
	bool AButtonIsClicked;

public:

	WindowDataCollection(): Level( 0 )
	{
		AButtonIsClicked = FALSE;
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

	void Click( HWND hwnd )
	{
		AButtonIsClicked = TRUE;
		//SetActiveWindow( hwnd );
		//SetForegroundWindow( hwnd );

		printf("Sending a Message\n" );
		::SendMessage( hwnd, BM_SETSTATE, 1, 0 );
		::Sleep( 1000 );
		::SendMessage( hwnd, BM_CLICK, 0, 0 );
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

		DWORD dwProcessId;
		GetWindowThreadProcessId( hwnd, &dwProcessId );

		if( Level == 1 )
		{
			TopLevelText = Buffer;
			AButtonIsClicked  = FALSE;
		}

		//printf("%x: %s\n", hwnd, Buffer );
		//printf("[%s] Pid = %d\n", Buffer, dwProcessId );
		printf("[%s]\n", Buffer );

		if( Level > 1 )
		{
			//TODO: Separate clicking thread from enumeration thread
			/*
			if( TopLevelText == "Extraction Complete" ||
				TopLevelText == "Microsoft Internet Explorer Update" ||
				TopLevelText.find( "Security Update for " ) != std::string::npos ||
				TopLevelText.find( "Update for" ) != std::string::npos ||
				TopLevelText.find( "Hotfix" ) != std::string::npos ||
				TopLevelText.find( "hotfix" ) != std::string::npos ||
				TopLevelText.find( "Security Patch" ) != std::string::npos
			)
			{
				if( !strcmp( Buffer, "&OK" ) || !strcmp( Buffer, "OK" ) )
				{
					Click( hwnd );
				}
			}*/
			if( !strcmp( Buffer, "&OK" ) || !strcmp( Buffer, "OK" ) )
			{
				printf("Clicking [%s]\n", TopLevelText.c_str() );
				Click( hwnd );
			}
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

void ClickDialogs()
{
	//TODO: to do this in time interval
	WindowDataCollection *pWindowDataCollection = new WindowDataCollection();
	while( 1 )
	{
		BOOL ret = EnumWindows( EnumWindowsProc, (LPARAM)  pWindowDataCollection );
		//::Sleep(100);
	}
}


int main()
{
	ClickDialogs();
}
