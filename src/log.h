#pragma once

#define LOG_DEBUG(FORMAT, ...) fprintf(stderr, "LOG_DEBUG " FORMAT "\n", ## __VA_ARGS__)
#define LOG_ERROR(FORMAT, ...) fprintf(stderr, "LOG_ERROR " FORMAT "\n", ## __VA_ARGS__)
