#pragma once

#include <uv.h>

#include <stdio.h>

#define LOG_DEBUG(FORMAT, ...) fprintf(stderr, "LOG_DEBUG %p " FORMAT "\n", uv_thread_self(), ## __VA_ARGS__)
#define LOG_ERROR(FORMAT, ...) fprintf(stderr, "LOG_ERROR %p " FORMAT "\n", uv_thread_self(), ## __VA_ARGS__)
