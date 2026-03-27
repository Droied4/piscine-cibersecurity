#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char value[1024];	
	printf("Please enter key: ");	
	scanf("%s", value);
	if (!strcmp("__stack_check", value))
		printf("Good Job.\n");
	else
	 	printf("Nope.\n");
	return 0;
}
