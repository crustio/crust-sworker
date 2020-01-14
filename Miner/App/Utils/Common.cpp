#include "Common.h"

using namespace std;

extern FILE *felog;
extern const char *show_tag;

char _timeBuff[TIMESTR_SIZE];

/**
 * @description: print messages with indicated format to stderr
 *  if felog defined then output the messages to the file too
 * */
void edivider_with_text(const char *text)
{
	divider_with_text(stderr, text);
	if (felog != NULL)
		divider_with_text(felog, text);
}

/**
 * @description: print messages indicated stream
 * */
void divider_with_text(FILE *fd, const char *text)
{
	fprintf(fd, "\n%s\n", LINE_HEADER(text));
}

/**
 * @description: print end line with indicated format to stderr
 *  if felog defined then output the messages to the file too
 * */
void edivider()
{
	divider(stderr);
	if (felog != NULL)
		divider(felog);
}

/**
 * @description: print end line indicated stream
 * */
void divider(FILE *fd)
{
	fprintf(fd, "%s\n", LINE_COMPLETE);
}

/**
 * @description: print messages to stderr. If specific stream defined
 *  output messages to it.
 * @return: print status
 * */
int cfprintf(FILE *stream, const char *format, ...)
{
	va_list va;
	int rv;

	// Print timestamp
    char* p_timestr = print_timestamp();

	va_start(va, format);
	rv = vfprintf(stderr, format, va);
	va_end(va);

	if (stream != NULL)
	{
		if(!(strlen(format) == 1 && format[0] == '\n') && p_timestr != NULL)
		{
			fprintf(stream, "[%s] ", p_timestr);
		}
		va_start(va, format);
		rv = vfprintf(stream, format, va);
		va_end(va);
	}

	return rv;
}

int cfprintf_pro(FILE *stream, const char* processID, const char* type, const char *format, ...)
{
	va_list va;
	int rv;

	// Print timestamp
    char* p_timestr = print_timestamp();
    printf("%s%s", show_tag, processID);

	va_start(va, format);
	rv = vfprintf(stderr, format, va);
	va_end(va);

	if (stream != NULL)
	{
		if(!(strlen(format) == 1 && format[0] == '\n') && p_timestr != NULL)
		{
			fprintf(stream, "[%s] %s%s", p_timestr, show_tag, processID);
		}
		va_start(va, format);
		rv = vfprintf(stream, format, va);
		va_end(va);
	}

	return rv;
}

char* print_timestamp()
{
	// Print timestamp
	time_t ts;
	struct tm timetm, *timetmp;
    //char *_timeBuff = (char*)malloc(TIMESTR_SIZE);
    //memset(_timeBuff, 0, TIMESTR_SIZE);
	time(&ts);
#ifndef _WIN32
	timetmp = localtime(&ts);
	if (timetmp == NULL)
	{
		perror("localtime");
		return NULL;
	}
	timetm = *timetmp;
#else
	localtime_s(&timetm, &ts);
#endif

	/* If you change this format, you _may_ need to change TIMESTR_SIZE */
	if (strftime(_timeBuff, TIMESTR_SIZE, "%b %e %Y %T", &timetm) == 0)
	{
		/* oops */
		_timeBuff[0] = 0;
	}
	fprintf(stderr, "[%s] ", _timeBuff);

    return _timeBuff;
}

/**
 * @description: print messages to logfile if defined and stderr
 * @return: put status
 * */
int cfputs(const char *s)
{
	if (felog != NULL)
		fputs(s, felog);
	return fputs(s, stderr);
}
