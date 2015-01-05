
#include <stdio.h>

#include <unistd.h>
#include <fcntl.h>



int main (int argc, char *argv[]) {
	char buf[128];
	int ret;
	
	/*
	//ret = sprintf (buf, "-%s-", "123");
	//printf("Str: %s, Size: %d\n", buf, ret);
	if (argc > 1) {
		printf (argv[1]);
		printf ("\n");
	}
	else printf ("No params\n");
	*/
	
	//
	// в файле fcntl.h - эти констнты заданы в 8-ричной системе
	//
	printf ("Vars in dec: %d-%d-%d\n", O_CREAT, O_WRONLY, O_TRUNC);
	printf ("Vars in hex: 0x%08X-0x%08X-0x%08X\n", O_CREAT, O_WRONLY, O_TRUNC);
	
	return 0;
}
