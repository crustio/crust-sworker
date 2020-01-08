#ifndef __COMMON_H
#define __COMMON_H

/* Help keep our console messages clean and organzied */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <cstdio>
#include <cstring>
#include <string>

#define LINE_TYPE '-'
#define LINE_SHORT_LEN 4
#define LINE_MAX_LEN 76
#define LINE_TRAILING_LEN(header) ((LINE_MAX_LEN - string(header).size()) - LINE_SHORT_LEN - 2)

#define LINE_COMPLETE (string(LINE_MAX_LEN, LINE_TYPE).c_str())

#define LINE_HEADER(header) (string(string(LINE_SHORT_LEN, LINE_TYPE) + ' ' + string(header) + ' ' + string(LINE_TRAILING_LEN(header), LINE_TYPE)).c_str())

#define INDENT(level) (string(level, ' '))

#define WARNING_INDENT(level) (string(level, '*'))

#define TIMESTR_SIZE 64

#define CF_INFO "[INFO] "
#define CF_WARN "[WARN] "
#define CF_ERROR "[ERROR] "

#if defined(__cplusplus)
extern "C"
{
#endif

    void edivider_with_text(const char *text);
    void edivider();

    void divider_with_text(FILE *fd, const char *text);
    void divider(FILE *fd);

    int cfprintf(FILE *stream, const char *format, ...);
    char* print_timestamp();
    int cfputs(const char *s);

#if defined(__cplusplus)
}
#endif

#endif
