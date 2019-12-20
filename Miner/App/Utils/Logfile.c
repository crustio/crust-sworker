#include "Logfile.h"

FILE *felog = NULL;

FILE *fplog = NULL;

/**
 * @description: create log file
 * @return: created file
 * */
FILE *create_logfile(const char *filename)
{
	FILE *fp;

#ifdef _WIN32
	if (fopen_s(&fp, filename, "w") != 0) {
		fprintf(stderr, "fopen_s: ");
#else
	//if ( (fp= fopen(filename, "w")) == NULL ) {
	if ( (fp= fopen(filename, "a")) == NULL ) {
		fprintf(stderr, "fopen: ");
#endif
		perror(filename);
		exit(1);
	}

	return fp;
}

/**
 * @description: close log file
 * */
void close_logfile (FILE *fp)
{
	if ( fp ) {
		fclose(fp);
		fp = NULL;
	}
}
