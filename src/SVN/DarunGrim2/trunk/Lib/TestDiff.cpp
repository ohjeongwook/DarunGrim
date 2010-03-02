#include <stdio.h>
#include "Varray.h"
#include "Diff.h"

int main(int argc,char *argv[])
{
	const char *a=argv[1];
	const char *b=argv[2];
	int n,m,d;
	int sn,i;
	struct varray ses;

	varray_init(&ses,sizeof(DiffEdit),NULL);
	if (argc < 3) {
		fprintf(stderr,"usage: %s <str1> <str2>\n",argv[0]);
		return EXIT_FAILURE;
	}

	n=strlen(a);
	m=strlen(b);
	if ((d=DiffArray(
		a,0,n,
		b,0,m,
		NULL,0,&ses,&sn,NULL)) == -1) 
	{
		return EXIT_FAILURE;
	}

	printf("d=%d sn=%d\n",d,sn);
	for (i=0; i < sn; i++) {
		DiffEdit *e=(DiffEdit *)varray_get(&ses,i);
		switch (e->op) {
			case DIFF_MATCH:
				printf("MAT: ");
				fwrite(a + e->off,1,e->len,stdout);
				break;
			case DIFF_INSERT:
				printf("INS: ");
				fwrite(b + e->off,1,e->len,stdout);
				break;
			case DIFF_DELETE:
				printf("DEL: ");
				fwrite(a + e->off,1,e->len,stdout);
				break;
		}
		printf("\n");
	}
	printf("Similarity: %d %%\n",GetStringSimilarity(a,b));
        return(0);
}
