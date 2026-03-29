#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void no(void)
{
	printf("Nope.\n");
	exit(1);
}

void ok(void)
{
	printf("Good Job.\n");
	exit(1);
}

int main(void)
{
    char value[1024];	
	char result[1024];
	int ascii = 0;
	printf("Please enter key: ");	
	scanf("%s", value);
	int len = strlen(value);
	printf("len -> %d \n", len);
	if (len < 23)
		no();
	if (value[0] != '0')
		no();
	if (value[1] != '0')
		no();
	int i = 2;
	int a = 1;
	result[0] = 'd';
	char number[4]; 
	while(i < len)
  	{
		strncpy(number,value + i, 3);
		number[3] = '\0';
	   	ascii = atoi(number);
		printf("number -> %d \n", ascii);
		result[a] = ascii;
		a++;
		i += 3;
	}
	result[a] = '\0';
	if (!strcmp(result, "delabere"))
		ok();
	else
	 no();
	return 0;
}
