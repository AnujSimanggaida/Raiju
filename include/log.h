#ifndef LOG_H
#define LOG_H

/*
 * log.h - Minimal leveled logging
 */

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3
} log_level_t;

/* Sets the minimum level that will actually be printed. Default: LOG_INFO. */
void log_set_level(log_level_t level);

/* printf-style logging at the given level. Includes level tag and
 * (for DEBUG) file/line info via the LOG_* macros below. */
void log_write(log_level_t level, const char *fmt, ...);

#define LOG_ERRORF(...) log_write(LOG_ERROR, __VA_ARGS__)
#define LOG_WARNF(...)  log_write(LOG_WARN,  __VA_ARGS__)
#define LOG_INFOF(...)  log_write(LOG_INFO,  __VA_ARGS__)
#define LOG_DEBUGF(...) log_write(LOG_DEBUG, __VA_ARGS__)

#endif /* LOG_H */
