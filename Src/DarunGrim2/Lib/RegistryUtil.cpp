#include "RegistryUtil.h"

char *GetRegValue( const char *key_name, const char *value_name, DWORD &type, DWORD &data_length )
{
	HKEY root_key ;

	if( !_strnicmp( key_name, "HKEY_LOCAL_MACHINE", 18 ) )
	{
		root_key = HKEY_LOCAL_MACHINE;
	}
	else if( !_strnicmp( key_name, "HKEY_CLASSES_ROOT", 17 ) )
	{
		root_key = HKEY_CLASSES_ROOT;
	}
	else if( !_strnicmp( key_name, "HKEY_CURRENT_USER", 17 ) )
	{
		root_key = HKEY_CURRENT_USER;
	}
	else if( !_strnicmp( key_name, "HKEY_USERS", 10 ) )
	{
		root_key = HKEY_USERS;
	}
	else if( !_strnicmp( key_name, "HKEY_CURRENT_CONFIG", 19 ) )
	{
		root_key = HKEY_CURRENT_CONFIG;
	}

	char *subkey_name = (char *)strstr( key_name, "\\" );
	subkey_name++;
	HKEY hk_result;
	if( RegOpenKey( root_key, subkey_name, &hk_result ) == ERROR_SUCCESS )
	{
		BYTE *data;
		data_length = 1;

		data = (BYTE *) malloc( data_length );
		while( 1 )
		{
			LONG Ret = RegQueryValueEx( hk_result, value_name, 0, &type, data, &data_length );
			if( Ret == ERROR_MORE_DATA )
			{
				data_length += 1;
				data = (BYTE *) realloc( data, data_length );
				continue;
			}
			if( Ret == ERROR_SUCCESS )
			{
				return (char *)data;	
			}
			break;
		}
		free( data );
		RegCloseKey( hk_result );
	}

	return NULL;
}


char *GetRegValueString( const char *key_name, const char *value_name )
{
	DWORD type;
	DWORD data_length;
	char *data = GetRegValue( key_name, value_name, type, data_length );

	if( data )
	{
		if( type == REG_SZ )
		{
			return data;
		}
		free(data);
	}
	return NULL;
}

bool GetRegValueInteger( const char *key_name, const char *value_name, DWORD &value )
{
	DWORD type;
	DWORD data_length;

	char *data = GetRegValue( key_name, value_name, type, data_length );

	if( data )
	{
		if( type == REG_DWORD && data_length == sizeof( DWORD ) )
		{
			memcpy( &value, data, data_length );
			return true;
		}
		free(data);
	}
	return false;
}

