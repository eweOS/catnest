#include<stdio.h>

int main()
{
	FILE *fp = fopen("test.txt","a+");
	rewind(fp);
	fputs("add",fp);
	fclose(fp);
	return 0;
}
