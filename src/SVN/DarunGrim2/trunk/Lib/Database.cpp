#include "Database.h"
#include "FileInfo.h"
#include "IdaIncludes.h"

char *table_postfix=NULL;
long file_id=0;
extern char *output_filename=NULL;

static int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
	int i;
	for(i=0; i<argc; i++){
		msg("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	msg("\n");
	return 0;
}

int ExecuteStatement(sqlite3 *db,char *format, ...)
{
	int debug=0;

	if(db)
	{
		va_list args;
		va_start(args,format);
		char statement_buffer[1024*3]={0,};
		_vsnprintf(statement_buffer,sizeof(statement_buffer),format,args);
		va_end(args);
		char *zErrMsg=0;
		if(debug>1)
		{
			msg("Executing [%s]\n",statement_buffer);
		}
		int rc=sqlite3_exec(db,statement_buffer,callback,0,&zErrMsg);
		if(rc!=SQLITE_OK)
		{
			if(debug>0)
			{
				msg("SQL error: [%s] [%s]\n",statement_buffer,zErrMsg);
			}
		}
		return rc;
	}
	return SQLITE_ERROR;
}

sqlite3 *InitializeDatabase(int arg)
{	
#ifdef _USE_IDA_SDK_49_OR_UPPER
	char orignal_file_path[1024]={0,};
	char root_file_path[1024]={0,};
#else
	char *orignal_file_path=strdup(get_input_file_path());
	char *root_file_path=get_root_filename();
#endif
	char *input_file_path=NULL;
#ifdef _USE_IDA_SDK_49_OR_UPPER
	get_input_file_path(orignal_file_path,sizeof(orignal_file_path)-1);
	get_root_filename(root_file_path,sizeof(root_file_path)-1);
#endif
	if(arg==0)
	{
		input_file_path=askfile_c(1,"*.db","Select DB File to Output");
		if(!input_file_path)
		{
			return NULL;
		}
	}else{
		input_file_path=output_filename;
	}
	char *rd_file_path=NULL;
	if(input_file_path && strlen(input_file_path)>0)
	{
		int rd_file_path_size=strlen(input_file_path)+5;
		rd_file_path=(char *)calloc(1,rd_file_path_size);
		if(rd_file_path)
		{
			qstrncpy(rd_file_path,input_file_path,rd_file_path_size);
#define DB_POSTFIX ".db"
			if(stricmp(&input_file_path[strlen(input_file_path)-3],".db"))
			{
#ifdef _USE_IDA_SDK_49_OR_UPPER
				qstrncat(rd_file_path,DB_POSTFIX,rd_file_path_size);
#else
#ifdef _USE_IDA_SDK_47_OR_LOWER
				strncat(rd_file_path,DB_POSTFIX,rd_file_path_size);
#else
				qstrncat(rd_file_path,DB_POSTFIX,rd_file_path_size);
#endif
#endif
			}
			msg("Output file=[%s]\n",rd_file_path);
		}
	}
	if(!rd_file_path)
	{
		return NULL;
	}
	//msg("arg=%d orignal_file_path=%s root_file_path=%s input_file_path=%s rd_file_path=%s\n",arg,orignal_file_path,root_file_path,input_file_path,rd_file_path);
	//show_wait_box("Generating DB file: [%s]\n",rd_file_path);

	sqlite3 *db=NULL;
	int rc=sqlite3_open(rd_file_path,&db);
	if(rc)
	{
		sqlite3_close(db);
		db=NULL;
	}
	if(db)
	{
		ExecuteStatement(db,"CREATE TABLE TargetBinaries(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			filename VARCHAR(40),\n\
			pathname VARCHAR(255),\n\
			operating_system VARCHAR(40),\n\
			generated_on VARCHAR(40),\n\
			generated_by VARCHAR(40),\n\
			analysis_start DATETIME,\n\
			analysis_end DATETIME,\n\
			company_name VARCHAR(40),\n\
			file_version VARCHAR(40),\n\
			file_description VARCHAR(40),\n\
			internal_name VARCHAR(40),\n\
			product_name VARCHAR(40),\n\
			modified_time DATETIME,\n\
			md5_sum VARCHAR(40),\n\
			table_postfix VARCHAR(40) NOT NULL\n\
		);");

#define HEX_NUM 10
		table_postfix=new char[HEX_NUM*2+1];
		srand((unsigned)time(NULL));
		/* Display 10 numbers. */
		for(int i=0;i<HEX_NUM;i++)
			qsnprintf(table_postfix+i*2,3,"%.2x",rand()/255);

		////////// Collect Information about current system and target file

		////about system and user
		TCHAR ComputerName[1024];
		DWORD ComputerNameLen=sizeof(ComputerName);
		GetComputerName(ComputerName,&ComputerNameLen);
		TCHAR UserName[1024];
		DWORD UserNameLen=sizeof(UserName);
		GetUserName(UserName,&UserNameLen);

		////about file
		char *modified_time_str="";
		char *md5_sum_str="";
		char *company_name_str="";
		char *file_version_str="";
		char *file_description_str="";
		char *internal_name_str="";
		char *product_name_str="";

		char *modified_time=GetLastWriteTime(orignal_file_path);
		if(modified_time)
		{
			modified_time_str=modified_time;
			msg("modified time=%s\n",modified_time);
		}

		char *md5_sum=GetFileMD5Sum(orignal_file_path);
		if(md5_sum)
		{
			md5_sum_str=md5_sum;
			msg("md5_sum=%s\n",md5_sum);
		}

		char *company_name=GetFileVersionInfoStr(orignal_file_path,"CompanyName");
		if(company_name)
		{
			company_name_str=company_name;
			msg("company_name=%s\n",company_name);
		}
		char *file_version=GetFileVersionInfoStr(orignal_file_path,"FileVersion");
		if(file_version)
		{
			file_version_str=file_version;
			msg("file_version=%s\n",file_version);
		}
		char *file_description=GetFileVersionInfoStr(orignal_file_path,"FileDescription");
		if(file_description)
		{
			file_description_str=file_description;
			msg("file_description=%s\n",file_description);
		}
		char *internal_name=GetFileVersionInfoStr(orignal_file_path,"InternalName");
		if(internal_name)
		{
			internal_name_str=internal_name;
			msg("internal_name=%s\n",internal_name);
		}
		char *product_name=GetFileVersionInfoStr(orignal_file_path,"ProductName");
		if(product_name)
		{
			product_name_str=product_name;
			msg("product_name=%s\n",product_name);
		}

		ExecuteStatement(db,"INSERT INTO TargetBinaries \n\
				(filename,pathname,generated_on,generated_by,analysis_start,table_postfix,company_name,file_version,file_description,internal_name,product_name,modified_time,md5_sum) \n\
				values \n\
				('%s','%s','%s','%s',DATETIME('NOW'),'%s','%s','%s','%s','%s','%s','%s','%s');",
				root_file_path,orignal_file_path,ComputerName,UserName,table_postfix,
				company_name_str,file_version_str,file_description_str,internal_name_str,product_name_str,modified_time_str,md5_sum_str);
#ifndef _USE_IDA_SDK_49_OR_UPPER
		free(orignal_file_path);
#endif
		/*
		if(company_name)
			free(company_name);
		if(file_version)
			free(file_version);
		if(file_description)
			free(file_description);
		if(internal_name)
			free(internal_name);
		if(product_name)
			free(product_name);
		if(modified_time)
			free(modified_time);
		*/

		file_id=(long)sqlite3_last_insert_rowid(db);
#ifdef USE_FUNCTIONS_TABLE
		ExecuteStatement(db,"CREATE TABLE Functions_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			name VARCHAR(40)UNIQUE,\n\
			start INTEGER,\n\
			end INTEGER,\n\
			file_id INTEGER\n\
		);",table_postfix);
#endif

		ExecuteStatement(db,"CREATE TABLE Names_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			address INTEGER UNIQUE,\n\
			name VARCHAR(40),\n\
			type VARCHAR(5)\n\
		);",table_postfix);

		ExecuteStatement(db,"CREATE TABLE Maps_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			function_address INTEGER,\n\
			src_block_address INTEGER,\n\
			src INTEGER,\n\
			op VARCHAR(40),\n\
			relation VARCHAR(40),\n\
			dst INTEGER\n\
		);",table_postfix);

		ExecuteStatement(db,"CREATE TABLE Stack_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			function_address INTEGER,\n\
			name VARCHAR(40),\n\
			start INTEGER,\n\
			end INTEGER\n\
		);",table_postfix);

		ExecuteStatement(db,"CREATE TABLE Data_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			address VARCHAR(40) UNIQUE,\n\
			flag INTEGER,\n\
			data TEXT\n\
		);",table_postfix);

		ExecuteStatement(db,"CREATE TABLE DisasmLines_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			address INTEGER UNIQUE,\n\
			op VARCHAR(40),\n\
			op1 VARCHAR(40),\n\
			op1_offset INTEGER,\n\
			op2 VARCHAR(40),\n\
			op2_offset INTEGER,\n\
			comment VARCHAR(40),\n\
			block_address INTEGER\n\
		);",table_postfix);

		ExecuteStatement(db,"CREATE TABLE FingerPrints_%s(\n\
			id INTEGER PRIMARY KEY AUTOINCREMENT,\n\
			address INTEGER,\n\
			type VARCHAR(10),\n\
			fingerprint VARCHAR(256)\n\
		);",table_postfix);
	}
	free(rd_file_path);
	ExecuteStatement(db,"BEGIN");
	return db;
}

void DeInitializeDatabase(sqlite3 *db)
{
	ExecuteStatement(db,"COMMIT");
	ExecuteStatement(db,"END");
	ExecuteStatement(db,"UPDATE TargetBinaries SET analysis_end=DATETIME('NOW') WHERE id='%d';",file_id);
	sqlite3_close(db);
	if(table_postfix)
	{
		delete table_postfix;
	}
}

void SaveToDatabase(sqlite3 *db,AddrMapHash *addr_map_base,LocationInfo *p_first_location_info)
{
	LocationInfo *p_current_location_info;
	bool is_positive_jmp=FALSE;

	for(p_current_location_info=p_first_location_info;p_current_location_info;p_current_location_info=p_current_location_info->next)
	{
		if(p_current_location_info->saved)
			continue;
		p_current_location_info->saved=TRUE;
		LocationInfo *p_location_info=p_current_location_info;

		if(isCode(p_current_location_info->flag))
		{
			char fingerprint_data[1024*5];
			size_t fingerprint_i=0;

			while(p_location_info)
			{
				for(ea_t current_address=p_location_info->address;
					current_address<p_location_info->address+p_location_info->block_size &&
					fingerprint_i+7<(sizeof(fingerprint_data)/sizeof(char));
					current_address+=get_item_size(current_address)
				)
				{
					//dump disasmline
					char op_buffer[100]={0,};
					char operand_buffers[UA_MAXOP][MAXSTR+1];
					ea_t offsets[UA_MAXOP]={0,};
					bool save_fingerprint=TRUE;

					ua_mnem(current_address,op_buffer,sizeof(op_buffer));

					if(
						cmd.itype==NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
						cmd.itype==NN_jae ||                 // Jump if Above or Equal (CF=0)
						cmd.itype==NN_jc ||                  // Jump if Carry (CF=1)
						cmd.itype==NN_jcxz ||                // Jump if CX is 0
						cmd.itype==NN_jecxz ||               // Jump if ECX is 0
						cmd.itype==NN_jrcxz ||               // Jump if RCX is 0
						cmd.itype==NN_je ||                  // Jump if Equal (ZF=1)
						cmd.itype==NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
						cmd.itype==NN_jge ||                 // Jump if Greater or Equal (SF=OF)
						cmd.itype==NN_jo ||                  // Jump if Overflow (OF=1)
						cmd.itype==NN_jp ||                  // Jump if Parity (PF=1)
						cmd.itype==NN_jpe ||                 // Jump if Parity Even (PF=1)
						cmd.itype==NN_js ||                  // Jump if Sign (SF=1)
						cmd.itype==NN_jz ||                  // Jump if Zero (ZF=1)
						cmd.itype==NN_jmp ||                 // Jump
						cmd.itype==NN_jmpfi ||               // Indirect Far Jump
						cmd.itype==NN_jmpni ||               // Indirect Near Jump
						cmd.itype==NN_jmpshort ||            // Jump Short
						cmd.itype==NN_jpo ||                 // Jump if Parity Odd  (PF=0)
						cmd.itype==NN_jl ||                  // Jump if Less (SF!=OF)
						cmd.itype==NN_jle ||                 // Jump if Less or Equal (ZF=1 | SF!=OF)
						cmd.itype==NN_jb ||                  // Jump if Below (CF=1)
						cmd.itype==NN_jbe ||                 // Jump if Below or Equal (CF=1 | ZF=1)
						cmd.itype==NN_jna ||                 // Jump if Not Above (CF=1 | ZF=1)
						cmd.itype==NN_jnae ||                // Jump if Not Above or Equal (CF=1)
						cmd.itype==NN_jnb ||                 // Jump if Not Below (CF=0)
						cmd.itype==NN_jnbe ||                // Jump if Not Below or Equal (CF=0 & ZF=0)
						cmd.itype==NN_jnc ||                 // Jump if Not Carry (CF=0)
						cmd.itype==NN_jne ||                 // Jump if Not Equal (ZF=0)
						cmd.itype==NN_jng ||                 // Jump if Not Greater (ZF=1 | SF!=OF)
						cmd.itype==NN_jnge ||                // Jump if Not Greater or Equal (ZF=1)
						cmd.itype==NN_jnl ||                 // Jump if Not Less (SF=OF)
						cmd.itype==NN_jnle ||                // Jump if Not Less or Equal (ZF=0 & SF=OF)
						cmd.itype==NN_jno ||                 // Jump if Not Overflow (OF=0)
						cmd.itype==NN_jnp ||                 // Jump if Not Parity (PF=0)
						cmd.itype==NN_jns ||                 // Jump if Not Sign (SF=0)
						cmd.itype==NN_jnz                 // Jump if Not Zero (ZF=0)
					)
					{
						save_fingerprint=FALSE;
						//map table
						//check last instruction whether it was positive or negative to tweak the map
						if(
							cmd.itype==NN_ja ||                  // Jump if Above (CF=0 & ZF=0)
							cmd.itype==NN_jae ||                 // Jump if Above or Equal (CF=0)
							cmd.itype==NN_jc ||                  // Jump if Carry (CF=1)
							cmd.itype==NN_jcxz ||                // Jump if CX is 0
							cmd.itype==NN_jecxz ||               // Jump if ECX is 0
							cmd.itype==NN_jrcxz ||               // Jump if RCX is 0
							cmd.itype==NN_je ||                  // Jump if Equal (ZF=1)
							cmd.itype==NN_jg ||                  // Jump if Greater (ZF=0 & SF=OF)
							cmd.itype==NN_jge ||                 // Jump if Greater or Equal (SF=OF)
							cmd.itype==NN_jo ||                  // Jump if Overflow (OF=1)
							cmd.itype==NN_jp ||                  // Jump if Parity (PF=1)
							cmd.itype==NN_jpe ||                 // Jump if Parity Even (PF=1)
							cmd.itype==NN_js ||                  // Jump if Sign (SF=1)
							cmd.itype==NN_jz ||                  // Jump if Zero (ZF=1)
							cmd.itype==NN_jmp ||                 // Jump
							cmd.itype==NN_jmpfi ||               // Indirect Far Jump
							cmd.itype==NN_jmpni ||               // Indirect Near Jump
							cmd.itype==NN_jmpshort            // Jump Short
							)
						{
							is_positive_jmp=TRUE;
						}else{
							is_positive_jmp=FALSE;
						}
					}

					//cmd.Operands[i].type
					//dtyp
					if(save_fingerprint)
					{
						fingerprint_data[fingerprint_i++]=cmd.itype;
					}

					if(cmd.auxpref&aux_rep || cmd.auxpref&aux_repne)
					{
						generate_disasm_line(current_address,op_buffer,sizeof(op_buffer),0);
						tag_remove(op_buffer,op_buffer,sizeof(op_buffer));
					}

					for(int i=0;i<UA_MAXOP;i++)
					{
						memset(operand_buffers[i],0,sizeof(operand_buffers[i]));

						if(cmd.Operands[i].type>0)
						{
							if(ua_outop(current_address,operand_buffers[i],sizeof(operand_buffers[i]),i))
							{
								tag_remove(operand_buffers[i],operand_buffers[i],sizeof(operand_buffers[i]));
								if(cmd.Operands[i].type==o_phrase || cmd.Operands[i].type==o_displ)
								{
									op_t operand=cmd.Operands[i];
									sval_t actval;
									member_t *stkvar_p=get_stkvar(operand,operand.addr,&actval);
									if(stkvar_p)
									{
										offsets[i]=stkvar_p->soff;
									}
								}
							}
							if(save_fingerprint)
							{
								fingerprint_data[fingerprint_i++]=cmd.Operands[i].type;
								fingerprint_data[fingerprint_i++]=cmd.Operands[i].dtyp;
								if(cmd.Operands[i].type==o_imm)
								{
									if(IsNumber(operand_buffers[i]))
									{
										fingerprint_data[fingerprint_i++]=(cmd.Operands[i].value>>8)&0xff;
										fingerprint_data[fingerprint_i++]=cmd.Operands[i].value&0xff;
									}
								}
							}
						}
					}
					ExecuteStatement(db,"INSERT INTO DisasmLines_%s (address,op,op1,op1_offset,op2,op2_offset,comment,block_address) \
						values ('%u','%s','%s','%u','%s','%u','%s','%u');",
						table_postfix,
						current_address,
						op_buffer,
						operand_buffers[0],offsets[0],
						operand_buffers[1],offsets[1],
						NULL,
						p_current_location_info->address);
				}
				if(!p_location_info->linked_node)
					break;
				p_location_info=p_location_info->linked_node;
			} //while(p_location_info)

			//insert fingerprint
			if(fingerprint_i>0)
			{
				DWORD blob_buffer_size=fingerprint_i*2*2+1;
				char *blob_buffer=(char *)new char[blob_buffer_size];
				for(size_t i=0;i<fingerprint_i;i++)
				{
					qsnprintf(blob_buffer+i*2,3,"%.2x",fingerprint_data[i]);
				}
				fingerprint_i=0;
				ExecuteStatement(db,"INSERT INTO FingerPrints_%s (address,type,fingerprint) values ('%u','code',x'%s');",
					table_postfix,
					p_current_location_info->address,
					blob_buffer);
				delete blob_buffer;
			}
		}else{
			//if data
			//TODO: dump to data
		}
		ea_t function_addresses_array[1]={0};
		ea_t *function_addresses=function_addresses_array;
		int function_addresses_size=1;
		if(p_location_info->function_addresses_size>0)
		{
			function_addresses=p_location_info->function_addresses;
			function_addresses_size=p_location_info->function_addresses_size;
		}

		for(int i=0;i<function_addresses_size;i++)
		{
			if(is_positive_jmp)
			{
				for(int j=0;j<p_location_info->next_crefs_size;j++)
				{
					ExecuteStatement(db,
						"INSERT INTO Maps_%s (function_address,src_block_address,src,op,relation,dst) values ('%u','%u','%u','%s','%s','%u');",
						table_postfix,
						function_addresses[i],
						p_current_location_info->address,
						p_current_location_info->address, //!!
						"j",
						"CREF",
						p_location_info->next_crefs[j]);
				}
			}else{
				for(int j=p_location_info->next_crefs_size-1;0<=j;j--)
				{
					ExecuteStatement(db,
						"INSERT INTO Maps_%s (function_address,src_block_address,src,op,relation,dst) values ('%u','%u','%u','%s','%s','%u');",
						table_postfix,
						function_addresses[i],
						p_current_location_info->address,
						p_current_location_info->address,
						"j",
						"CREF",
						p_location_info->next_crefs[j]);
				}
			}
			//call
			for(int j=0;j<p_location_info->call_addrs_size;j++)
			{
				ExecuteStatement(db,
					"INSERT INTO Maps_%s (function_address,src_block_address,src,op,relation,dst) values ('%u','%u','%u','%s','%s','%u');",
					table_postfix,
					function_addresses[i],
					p_current_location_info->address,
					p_current_location_info->address, //!!
					"call",
					"CREF",
					p_location_info->call_addrs[j]);
			}
			// dref
			for(int j=0;j<p_location_info->next_drefs_size;j++)
			{
				ExecuteStatement(db,
					"INSERT INTO Maps_%s (function_address,src_block_address,src,op,relation,dst) values ('%u','%u','%u','%s','%s','%u');",
					table_postfix,
					function_addresses[i],
					p_current_location_info->address,
					p_current_location_info->address,
					"",
					"DREF",
					p_location_info->next_drefs[j]);
			}
		}


		//function group table
		//function_addr,addr
		char name[100];
		if(!get_true_name(p_current_location_info->address,p_current_location_info->address,name,sizeof(name)))
		{
			qsnprintf(name,sizeof(name),"loc_%x",p_current_location_info->address);
		}

		char *type="loc";
		if(p_current_location_info->block_type==FUNCTION)
		{
			type="function";
		}
		ExecuteStatement(db,"INSERT INTO Names_%s (address,name,type) values ('%u','%s','%s');",
				table_postfix,
				p_current_location_info->address,
				name,
				type);

		//Only when it's function
		if(p_current_location_info->block_type==FUNCTION)
		{
#ifdef USE_FUNCTIONS_TABLE
			ExecuteStatement(db,"INSERT INTO Functions_%s (name,start,end,file_id) values ('%s','%u','%u','%u');",
				table_postfix,
				function_name,
				p_current_location_info->address,
				0,
				0);
#endif
			struc_t *p_frame=get_frame(get_func(p_current_location_info->address));
				
			if(p_frame)
			{
				for(size_t i=0;i<p_frame->memqty;i++)
				{

#ifdef _USE_IDA_SDK_49_OR_UPPER
					char struc_name[1024]={0,};
					get_struc_name(p_frame->members[i].id,struc_name,sizeof(struc_name));
#else
					char *struc_name=get_struc_name(p_frame->members[i].id);
#endif
					ExecuteStatement(db,"INSERT INTO Stack_%s (function_address,name,start,end) values ('%u','%s','%u','%u');",
						table_postfix,
						p_current_location_info->address,
						struc_name,
						p_frame->members[i].soff,
						p_frame->members[i].eoff);
				}
			}
		}
	}
}
