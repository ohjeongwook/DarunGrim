#pragma once
#include <stdio.h>
#include "sqlite3.h"

class DBWrapper
{
private:
	sqlite3 *db;
public:
	DBWrapper( char *DatabaseName = NULL )
	{
		db=NULL;
		if( DatabaseName )
			CreateDatabase( DatabaseName );
	}

	~DBWrapper()
	{
		CloseDatabase();
	}

	BOOL Open( char *DatabaseName )
	{
		CreateDatabase( DatabaseName );
	}

	void CloseDatabase()
	{
		//Close Database
		if(db)
		{
			sqlite3_close(db);
			db=NULL;
		}
	}

	BOOL CreateDatabase( char *DatabaseName )
	{		
		//Database Setup
		printf("Opening Database [%s]\n", DatabaseName );
		int rc = sqlite3_open( DatabaseName, &db );
		if(rc)
		{
			printf("Opening Database [%s] Failed\n", DatabaseName );
			sqlite3_close(db);
			db=NULL;
			return FALSE;
		}
		return TRUE;
	}

	int BeginTransaction()
	{
		return ExecuteStatement(NULL,NULL,"BEGIN TRANSACTION");
	}

	int EndTransaction()
	{
		return ExecuteStatement(NULL,NULL,"COMMIT");
	}

	int GetLastInsertRowID()
	{
		return (int)sqlite3_last_insert_rowid(db);
	}

	int ExecuteStatement( sqlite3_callback callback, void *context, char *format, ... )
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
				rc=sqlite3_exec(db, statement_buffer,callback, context, &zErrMsg );
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
				free( statement_buffer );
#else
				sqlite3_free( statement_buffer );
#endif
			}
			return rc;
		}
		return SQLITE_ERROR;
	}

	static int display_callback(void *NotUsed, int argc, char **argv, char **azColName)
	{
		int i;
		for(i=0; i<argc; i++){
			//msg("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
		}
		return 0;
	}

	static int ReadRecordIntegerCallback(void *arg,int argc,char **argv,char **names)
	{
#if DEBUG_LEVEL > 2
		printf("%s: arg=%x %d\n",__FUNCTION__,arg,argc);
		for(int i=0;i<argc;i++)
		{
			printf("	[%d] %s=%s\n",i,names[i],argv[i]);
		}
#endif
		*(int *)arg=atoi(argv[0]);
		return 0;
	}

	static int ReadRecordStringCallback(void *arg,int argc,char **argv,char **names)
	{
	#if DEBUG_LEVEL > 2
		printf("%s: arg=%x %d\n",__FUNCTION__,arg,argc);
		for(int i=0;i<argc;i++)
		{
			printf("	[%d] %s=%s\n",i,names[i],argv[i]);
		}
	#endif
		*(char **)arg=_strdup(argv[0]);
		return 0;
	}


};