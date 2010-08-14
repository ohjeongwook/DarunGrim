#include "RegistryUtil.h"

char *GetRegValueString( const char *KeyName, const char *ValueName )
{
	HKEY RootKey ;

	if( !_strnicmp( KeyName, "HKEY_LOCAL_MACHINE", 18 ) )
	{
		RootKey = HKEY_LOCAL_MACHINE;
	}
	else if( !_strnicmp( KeyName, "HKEY_CLASSES_ROOT", 17 ) )
	{
		RootKey = HKEY_CLASSES_ROOT;
	}
	else if( !_strnicmp( KeyName, "HKEY_CURRENT_USER", 17 ) )
	{
		RootKey = HKEY_CURRENT_USER;
	}
	else if( !_strnicmp( KeyName, "HKEY_USERS", 10 ) )
	{
		RootKey = HKEY_USERS;
	}
	else if( !_strnicmp( KeyName, "HKEY_CURRENT_CONFIG", 19 ) )
	{
		RootKey = HKEY_CURRENT_CONFIG;
	}

	char *SubKeyName = (char *)strstr( KeyName, "\\" );
	SubKeyName++;
	HKEY hkResult;
	if( RegOpenKey( RootKey, SubKeyName, &hkResult ) == ERROR_SUCCESS )
	{
		BYTE *Data;
		DWORD cbData = 1;
		DWORD Type;
		
		Data = (BYTE *) malloc( cbData );
		while( 1 )
		{
			LONG Ret = RegQueryValueEx( hkResult, ValueName, 0, &Type, Data, &cbData );
			if( Ret == ERROR_MORE_DATA )
			{
				cbData += 1;
				Data = (BYTE *) realloc( Data, cbData );
				continue;
			}
			if( Ret == ERROR_SUCCESS )
			{				
				if( Type == REG_SZ )
				{
					printf(" Data = %s\n", Data );
					return (char *)Data;					
				}
			}
		}
		free( Data );
		RegCloseKey( hkResult );
	}

	return NULL;
}
