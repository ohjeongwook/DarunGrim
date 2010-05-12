#include <windows.h>
#include <malloc.h>

#include "Python.h"

char win32ver_GetFileVersionInfo__doc__[] = 
	"GetFileVersionInfo(filename) -- Read File Version Information\n"
	"returns VersionInfo as a string";

PyObject *win32ver_GetFileVersionInfo( PyObject *self, PyObject *args )
{
	PyObject *result = NULL;
	char *filename;

	if( !PyArg_ParseTuple(args, "s", &filename ) )
		return NULL;
	
	DWORD handle = NULL;
	DWORD size = GetFileVersionInfoSize( filename, &handle );

	if( size != 0 )
	{
		char *buffer = static_cast<char *>(calloc( 1, size ) );
		if( buffer == NULL )
		{
			PyErr_SetString( PyExc_MemoryError, "win32ver: Out of Memory" );
			return NULL;
		}
		if( GetFileVersionInfo( filename, 0, size, buffer ) == 0 )
		{
			free( buffer );
			PyErr_SetString( PyExc_MemoryError, "win32ver: Cannot read version info" );
			return NULL;
		}

		result = Py_BuildValue( "s#", buffer, size );
		free( buffer );
		return result;
	}
	
	Py_INCREF( Py_None );
	return Py_None;
}

char win32ver_VerQueryValue__doc__[] = 
	"VerQueryValue(versioninfo, [subblock] ) -- Returns version\n"
	"information from the block retrieved by GetFileVersionInfo\n"
	"If subblock is omitted, it returns a list of tupes\n"
	"(language,codepage)\n";

PyObject *win32ver_VerQueryValue( PyObject *self, PyObject *args )
{
	PyObject *result = NULL;
	char *buffer;
	Py_UNICODE *subblock = NULL;
	unsigned int buflen;

	if( !PyArg_ParseTuple( args, "s#|u", &buffer, &buflen, &subblock ))
		return NULL;

	if( subblock == NULL )
	{
		PyObject *res = Py_BuildValue( "[]" );
		struct LANGANDCODEPAGE 
		{
			WORD wLanguage;
			WORD wCodePage;
		} *lpTranslate;

		unsigned int cbTranslate;

		VerQueryValueA( buffer, 
			TEXT("\\VarFileInfo\\Translation"),
			(LPVOID *)&lpTranslate,
			&cbTranslate );

		for( unsigned int i = 0; i < ( cbTranslate/sizeof( struct LANGANDCODEPAGE ) ); i++ )
		{
			PyObject *lc = Py_BuildValue( "(ii)", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage );
			if( lc == NULL || PyList_Append( res, lc ) < 0 )
			{
				Py_DECREF( res );
				return NULL;
			}
			Py_DECREF( lc );
		}
		return res;
	}
	else
	{
		Py_UNICODE *value;
		unsigned int size;
		if( VerQueryValueW( buffer, subblock, (LPVOID *)&value, &size ) != 0 )
		{
			PyObject *res = Py_BuildValue( "u", value );
			return res;
		}
	}
	Py_INCREF( Py_None );
	return Py_None;
}

static PyMethodDef win32ver_functions[] = {
	{ "GetFileVersionInfo", (PyCFunction) win32ver_GetFileVersionInfo, METH_VARARGS, win32ver_GetFileVersionInfo__doc__ },
	{ "VerQueryValue", (PyCFunction) win32ver_VerQueryValue, METH_VARARGS, win32ver_VerQueryValue__doc__ },
	{ NULL, NULL, 0, NULL }
};

void initwin32ver( void )
{
	PyObject *m = Py_InitModule3( "win32ver", win32ver_functions, "Win32 Version Info" );
}
