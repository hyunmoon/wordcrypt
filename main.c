#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/timeb.h>

#include <errno.h>
#include <limits.h>
#include <unistd.h>

void usage(int status, FILE * fp, const char *progname){
	fprintf(fp, "Usage: %s [d | e] [-vh] [-f f_arg] [-p password_arg] \n", progname);
	exit(status);
}

int main(int argc, char *argv[]){
	int opt;
	char de_or_en = 'e';

	char * filename;
	char * endptr;

	int dflag = 0;
	int eflag = 0;

	int val;
	if(stdin == NULL){
		fprintf(stderr, "Error: File not found");
		exit(1);
	}
	while((opt = getopt(argc,argv,"dehvf:p:")) != -1){
		switch(opt){
			case 'd'://decrypt, mutually exclusive with encrypt
				if(eflag){
					//exit out with error as it is mutually exclusive with encrypt option
					usage(EXIT_FAILURE,stderr,argv[0]);
				}

				de_or_en = 'd';
				dflag++;
				break;
			case 'e'://encrypt
				if(dflag){
					//exit out with error as it is mutually exclusive with decrypt option
					usage(EXIT_FAILURE,stderr,argv[0]);
				}

				de_or_en = 'e';
				eflag++;
				break;
			case 'h'://help
				usage(EXIT_SUCCESS,stdout,argv[0]);
				break;
			case 'f'://input file, must have filename argument
				input_filename
				printf("TEST: %s",optarg);
				break;
			default:
				usage(EXIT_FAILURE,stderr,argv[0]);
				exit(1);
		}
	}

	printf("\n DONE");
	
}
