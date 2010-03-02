#pragma warning(disable:4996)
#include <stdio.h>
#include "zlib.h"
#include <assert.h>

#define CHUNK 16384

/* Compress from file source to file dest until EOF on source.
	def() returns Z_OK on success,Z_MEM_ERROR if memory could not be
	allocated for processing,Z_STREAM_ERROR if an invalid compression
	level is supplied,Z_VERSION_ERROR if the version of zlib.h and the
	version of the library linked do not match,or Z_ERRNO if there is
	an error reading or writing the files. */

int def(FILE *source,FILE *dest,int level)
{
	int ret,flush;
	unsigned have;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];

	/* allocate deflate state */
	strm.zalloc=Z_NULL;
	strm.zfree=Z_NULL;
	strm.opaque=Z_NULL;
	ret=deflateInit(&strm,level);
	if(ret != Z_OK)
		return ret;

	/* compress until end of file */
	do 
	{
		strm.avail_in=fread(in,1,CHUNK,source);
		if(ferror(source)) 
		{
				(void)deflateEnd(&strm);
				return Z_ERRNO;
		}
		flush=feof(source) ? Z_FINISH : Z_NO_FLUSH;
		strm.next_in=in;

		/* run deflate() on input until output buffer not full,finish
			compression if all of source has been read in */
		do 
		{
				strm.avail_out=CHUNK;
				strm.next_out=out;
				ret=deflate(&strm,flush);	/* no bad return value */
				assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
				have=CHUNK - strm.avail_out;
				if(fwrite(out,1,have,dest) != have || ferror(dest)) 
				{
					(void)deflateEnd(&strm);
					return Z_ERRNO;
				}
		}while(strm.avail_out==0);
		assert(strm.avail_in==0);	/* all input will be used */

		/* done when last data in file processed */
	}while(flush!=Z_FINISH);
	assert(ret==Z_STREAM_END);		/* stream will be complete */

	/* clean up and return */
	(void)deflateEnd(&strm);
	return Z_OK;
}

/* Decompress from file source to file dest until stream ends or EOF.
	inf() returns Z_OK on success,Z_MEM_ERROR if memory could not be
	allocated for processing,Z_DATA_ERROR if the deflate data is
	invalid or incomplete,Z_VERSION_ERROR if the version of zlib.h and
	the version of the library linked do not match,or Z_ERRNO if there
	is an error reading or writing the files. */
int inf(FILE *source,FILE *dest)
{
	int ret;
	unsigned have;
	z_stream strm;
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];

	/* allocate inflate state */
	strm.zalloc=Z_NULL;
	strm.zfree=Z_NULL;
	strm.opaque=Z_NULL;
	strm.avail_in=0;
	strm.next_in=Z_NULL;
	ret=inflateInit(&strm);
	if(ret != Z_OK)
		return ret;

	/* decompress until deflate stream ends or end of file */
	do 
	{
		strm.avail_in=fread(in,1,CHUNK,source);
		if(ferror(source)) 
		{
				(void)inflateEnd(&strm);
				return Z_ERRNO;
		}
		if(strm.avail_in==0)
				break;
		strm.next_in=in;

		/* run inflate() on input until output buffer not full */
		do 
		{
			strm.avail_out=CHUNK;
			strm.next_out=out;
			ret=inflate(&strm,Z_NO_FLUSH);
			assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
			switch(ret) 
			{
				case Z_NEED_DICT:
					ret=Z_DATA_ERROR;	/* and fall through */
				case Z_DATA_ERROR:
				case Z_MEM_ERROR:
					(void)inflateEnd(&strm);
					return ret;
			}
			have=CHUNK-strm.avail_out;
			if(fwrite(out,1,have,dest)!=have||ferror(dest))
			{
				(void)inflateEnd(&strm);
				return Z_ERRNO;
			}
		}while(strm.avail_out==0);
		/*done when inflate() says it's done */
	}while(ret!=Z_STREAM_END);
	/* clean up and return */
	(void)inflateEnd(&strm);
	return ret==Z_STREAM_END?Z_OK:Z_DATA_ERROR;
}

int main()
{
	FILE *in=fopen("1.txt","rb");
	FILE *out=fopen("2.txt","wb");
	def(in,out,9);
	fclose(in);
	fclose(out);

	out=fopen("2.txt","rb");
	FILE *in2=fopen("3.txt","wb");
	inf(out,in2);
	return(0);
}

