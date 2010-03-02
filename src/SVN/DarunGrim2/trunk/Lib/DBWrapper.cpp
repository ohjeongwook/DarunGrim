#include <stdio.h>
#include <windows.h>
#include "sqlite3.h"

#ifdef IDA_PLUGIN
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <xref.hpp>
#include <intel.hpp>
#include <struct.hpp>
#endif

int ExecuteStatement(sqlite3 *db,sqlite3_callback callback,char *format, ...)
{
	int debug=0;

	if(db)
	{
		int rc;
		char *statement_buffer=NULL;
		char *zErrMsg=0;

		va_list args;
		va_start(args,format);
#ifdef USE_VSNPRINTF
		int statement_buffer_len=0;

		while(1)
		{
			statement_buffer_len+=1024;
			statement_buffer=(char *)malloc(statement_buffer_len);
			memset(statement_buffer,0,statement_buffer_len);
			if(statement_buffer && _vsnprintf(statement_buffer,statement_buffer_len,format,args)!=-1)
				break;
			if(!statement_buffer)
				break;
			free(statement_buffer);
		}
#else
		statement_buffer=sqlite3_vmprintf(format,args);
#endif
		va_end(args);

		if(debug>1)
		{
#ifdef IDA_PLUGIN			
			msg("Executing [%s]\n",statement_buffer);
#else
			printf("Executing [%s]\n",statement_buffer);
#endif
		}
		if(statement_buffer)
		{
			rc=sqlite3_exec(db,statement_buffer,callback,0,&zErrMsg);
			if(rc!=SQLITE_OK)
			{
				if(debug>0)
				{
#ifdef IDA_PLUGIN				
					msg("SQL error: [%s] [%s]\n",statement_buffer,zErrMsg);
#else
					printf("SQL error: [%s] [%s]\n",statement_buffer,zErrMsg);
#endif
				}
			}
#ifdef USE_VSNPRINTF
			free(statement_buffer);
#else
			sqlite3_free(statement_buffer);
#endif
		}
		return rc;
	}
	return SQLITE_ERROR;
}
