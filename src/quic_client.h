#pragma once

#include "quic_connection.h"

enum equic_client_t {
    EQUIC_CLIENT_OK,
    EQUIC_CLIENT_AGAIN = -1,
    EQUIC_CLIENT_INTERNAL = -2,
    EQUIC_CLIENT_CLOSED = -3,
    EQUIC_CLIENT_ILLEGAL_STATUS = -4,
    EQUIC_CLIENT_TIMEOUT = -5,
};

#define MAX_DATAGRAM_SIZE (1350)

class IQuicClientStreamIter {
public:
    virtual bool next(uint64_t *stream_id) = 0;
    virtual ~IQuicClientStreamIter() {};
};

class QuicClient {
public:
    QuicClient(const char *host, const char *port);
    ~QuicClient();

    equic_client_t connect();
    equic_client_t progress_while_connected();
    equic_client_t progress_while_timeout();
    ssize_t stream_send(uint64_t stream_id, const uint8_t *buf, size_t buf_len, bool finished);
    ssize_t stream_receive(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool *finished);
    IQuicClientStreamIter *readable();
    bool flush_egress();
    equic_client_t close(bool app, uint64_t err, const uint8_t *reason, size_t reason_len);

private:
    equic_client_t progress_while_connecting();

    int sock;
    char *host;
    char *port;
    QuicConnection *quic_connection;
};
