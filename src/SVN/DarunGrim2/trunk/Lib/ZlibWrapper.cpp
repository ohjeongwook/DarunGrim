#pragma warning(disable:4996)
#include <windows.h>
#include <stdio.h>
#include "ZlibWrapper.h"

#ifdef TEST_ZLIB_WRAPPER
int main2(int argc,char *argv[])
{
	ZlibWrapper *zlib_wrapper=new ZlibWrapper(TRUE);
	zlib_wrapper->SetOutFile("compressed.txt");
	for(int i=0;i<500;i++)
	{
		zlib_wrapper->WriteData((unsigned char *)"hh",2);
	}
	delete zlib_wrapper;

	zlib_wrapper=new ZlibWrapper(FALSE);
	zlib_wrapper->SetInFile("compressed.txt");
	//zlib_wrapper->SetOutFile("uncompressed.txt");
	unsigned char buffer[10+1]={0,};
	int ret;
	//do
	//{
		ret=zlib_wrapper->ReadData((unsigned char *)buffer,10);
		printf("decompressed=%s[%d bytes]\n",buffer,ret);
	//}while(ret>0);
	delete zlib_wrapper;
	return(0);
}

int main(int argc,char *argv[])
{
	if(argc<4)
	{
		printf("Usage: %s <comp|decomp> <input file> <output file>\n",argv[0]);
		exit(0);
	}
	BOOL bCompress=FALSE;
	if(!stricmp(argv[1],"comp"))
		bCompress=TRUE;
	ZlibWrapper *zlib_wrapper=new ZlibWrapper(bCompress);
	zlib_wrapper->SetInFile(argv[2]);
	zlib_wrapper->SetOutFile(argv[3]);
	zlib_wrapper->Write();
	delete zlib_wrapper;
}

#endif

