#pragma once

#include <stdlib.h>
#include <vector>
#include <sys/socket.h>

#define LOCAL_CONN_ID_LEN (16)
#define MAX_TOKEN_LEN (sizeof("quiche") - 1 + sizeof(struct sockaddr_storage) + QUICHE_MAX_CONN_ID_LEN)

class QuicHeaderInfo {
public:
    static std::unique_ptr<QuicHeaderInfo> parse(ssize_t len, const uint8_t *buf);

    uint8_t type;
    uint32_t version;
    std::vector<uint8_t> src_conn_id;
    std::vector<uint8_t> dst_conn_id;
    std::vector<uint8_t> token;

private:
    QuicHeaderInfo();
};
