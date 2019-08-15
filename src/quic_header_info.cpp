#include "quic_header_info.h"
#include "log.h"

#include <stdio.h>
#include <quiche.h>

std::unique_ptr<QuicHeaderInfo> QuicHeaderInfo::parse(ssize_t len, const uint8_t *buf) {
    uint8_t type;
    uint32_t version;

    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    size_t scid_len = sizeof(scid);

    uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
    size_t dcid_len = sizeof(dcid);

    uint8_t token[MAX_TOKEN_LEN];
    size_t token_len = sizeof(token);

    int rc = quiche_header_info(buf, len, LOCAL_CONN_ID_LEN, &version, &type,
                                scid, &scid_len, dcid, &dcid_len,
                                token, &token_len);
    if (rc < 0) {
        LOG_ERROR("failed to parse header: %d\n", rc);
        return std::unique_ptr<QuicHeaderInfo>(nullptr);
    }

    std::unique_ptr<QuicHeaderInfo> h(new QuicHeaderInfo());
    h->type = type;
    h->version = version;
    h->token = std::move(std::vector<uint8_t>(token, token + token_len));
    h->src_conn_id = std::move(std::vector<uint8_t>(scid, scid + scid_len));
    h->dst_conn_id = std::move(std::vector<uint8_t>(dcid, dcid + dcid_len));

    return std::move(h);
}

QuicHeaderInfo::QuicHeaderInfo() {
}
