#define _DEFAULT_SOURCE

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

/* log.c - see include/log.h for the contract */

static log_level_t current_level = LOG_INFO;

static const char *level_names[] = { "ERROR", "WARN", "INFO", "DEBUG" };

void log_set_level(log_level_t level) {
    current_level = level;
}

void log_write(log_level_t level, const char *fmt, ...) {
    if (level > current_level) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char stamp[16];
    strftime(stamp, sizeof(stamp), "%H:%M:%S", &tm);

    fprintf(stderr, "%s [%-5s] ", stamp, level_names[level]);

    /* va_list carries the "..." arguments through to vfprintf. */
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fputc('\n', stderr);
}
