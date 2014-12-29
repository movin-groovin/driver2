
#include <stdio.h>



int main (void) {
	char buf[128];
	int ret;
	
	ret = sprintf (buf, "-%s-", "123");
	printf("Str: %s, Size: %d\n", buf, ret);
	
	return 0;
}
