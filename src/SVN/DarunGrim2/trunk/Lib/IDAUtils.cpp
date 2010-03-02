#include "IDAUtils.h"

char *get_optype_str(optype_t optype)
{
	static char *optype_str[o_last+1]={0,};
	optype_str[o_void]="void";
	optype_str[o_reg]="reg";
	optype_str[o_mem]="mem";
	optype_str[o_phrase]="phrase";
	optype_str[o_displ]="displ";
	optype_str[o_imm]="imm";
	optype_str[o_far]="far";
	optype_str[o_near]="near";
	optype_str[o_idpspec0]="idpspec0";
	optype_str[o_idpspec1]="idpspec1";
	optype_str[o_idpspec2]="idpspec2";
	optype_str[o_idpspec3]="idpspec3";
	optype_str[o_idpspec4]="idpspec4";
	optype_str[o_idpspec5]="idpspec5";
	optype_str[o_last]="last";
	if(0<optype && optype<o_last)
		return optype_str[optype];
	else
		return "Unknown";
}

int get_current_operand_pos()
{
	int i;
	char *txt=get_curline();
	char* txt2=new char[MAXSTR];
	tag_remove(txt,txt2,MAXSTR);
	int x,y;
	get_cursor(&x,&y);
	for (i = 0; i < MAXSTR && txt2[i] != ','; i++);
	delete  txt2;
	if(x >i)
		return 1;
	return 0;
}

void DumpOptInfo(op_t opt,char *prefix="")
{
	msg("%stype=%s,reg=%d(%s),offb=%d,addr=%x,phrase=%d,value=%d,specflag1=%d ",
		prefix,
		get_optype_str(opt.type),
		opt.reg,
		ph.regNames[opt.reg],
		opt.offb,
		opt.addr,
		opt.phrase,
		opt.value,
		opt.specflag1
	);
	if(opt.hasSIB)
	{
		msg("sib_base=%s sib_index=%s",
			ph.regNames[sib_base(opt)],
			ph.regNames[sib_index(opt)]);
	}
	msg("\n");
}

void DumpCurrentOptInfo(ea_t address,int i)
{
	char operand[MAXSTR];
	ua_outop(address,operand,sizeof(operand)-1,i);
	tag_remove(operand,operand,0);
	msg("%s: ",operand);
	DumpOptInfo(cmd.Operands[i],"");
}
