#include "log.h"

LOG_LEVEL_E log_level = LOG_LEVEL_INFO;

void set_log_level(LOG_LEVEL_E level) {
    log_level = level;
}

void LOG_CONNECTION_ID(LOG_LEVEL_E level, const std::vector<uint8_t> &cid) {
    if (log_level >= level) {
        fprintf(stderr, "CONNECTION_ID ");
        for (auto it = cid.begin(); it != cid.end(); it++) {
            fprintf(stderr, "%02x", *it);
        }
        fprintf(stderr, "\n");
    }

}
