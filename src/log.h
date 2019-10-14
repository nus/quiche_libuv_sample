#pragma once

#include <uv.h>

#include <stdio.h>
#include <vector>

enum LOG_LEVEL_E {
    LOG_LEVEL_NONE,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG,
};

extern LOG_LEVEL_E log_level;

void set_log_level(LOG_LEVEL_E level);

#define LOG_ERROR(FORMAT, ...) do { if (log_level >= LOG_LEVEL_ERROR) fprintf(stderr, "LOG_ERROR " FORMAT "\n", ## __VA_ARGS__); } while(0)
#define LOG_INFO(FORMAT,  ...) do { if (log_level >= LOG_LEVEL_INFO)  fprintf(stderr, "LOG_INFO  " FORMAT "\n", ## __VA_ARGS__); } while(0)
#define LOG_DEBUG(FORMAT, ...) do { if (log_level >= LOG_LEVEL_DEBUG) fprintf(stderr, "LOG_DEBUG " FORMAT "\n", ## __VA_ARGS__); } while(0)
void LOG_CONNECTION_ID(LOG_LEVEL_E level, const std::vector<uint8_t> &cid);
