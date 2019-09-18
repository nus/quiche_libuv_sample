#pragma once

#include "quic_connection.h"

enum equic_client_t {
    EQUIC_CLIENT_OK = 0,
    EQUIC_CLIENT_AGAIN = 1,
    EQUIC_CLIENT_INTERNAL = 2,
    EQUIC_CLIENT_CLOSED = 2,
};

#define MAX_DATAGRAM_SIZE (1350)

class QuicClient {
public:
    QuicClient(const char *host, const char *port);
    ~QuicClient();

    equic_client_t connect();

private:
    bool flush_egress();

    int sock;
    char *host;
    char *port;
    QuicConnection *quic_connection;
};
