#ifndef __LOGFILE__H
#define __LOGFILE__H

#include <sys/types.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "FormatUtils.h"


#ifdef __cplusplus
extern "C" {
#endif

FILE *create_logfile(const char *filename);

void close_logfile (FILE *fp);

#ifdef __cplusplus
};
#endif

#endif
