
#include <stdio.h>



int main (int argc, char *argv[]) {
	char buf[128];
	int ret;
	
	//ret = sprintf (buf, "-%s-", "123");
	//printf("Str: %s, Size: %d\n", buf, ret);
	if (argc > 1) {
		printf (argv[1]);
		printf ("\n");
	}
	else printf ("No params\n");
	
	return 0;
}
