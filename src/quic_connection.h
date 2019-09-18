#pragma once

#include <stdio.h>
#include <quiche.h>
#include <vector>

// Same as values of quiche_error.
enum equick_socket_t {
    EQUIC_SOCKET_DONE = -1,
    EQUIC_SOCKET_BUFFER_TOO_SHORT = -2,
    EQUIC_SOCKET_UNKNOWN_VERSION = -3,
    EQUIC_SOCKET_INVALID_FRAME = -4,
    EQUIC_SOCKET_INVALID_PACKET = -5,
    EQUIC_SOCKET_INVALID_STATE = -6,
    EQUIC_SOCKET_INVALID_STREAM_STATE = -7,
    EQUIC_SOCKET_INVALID_TRANSPORT_PARAM = -8,
    EQUIC_SOCKET_CRYPTO_FAIL = -9,
    EQUIC_SOCKET_TLS_FAIL = -10,
    EQUIC_SOCKET_FLOW_CONTROL = -11,
    EQUIC_SOCKET_STREAM_LIMIT = -12,
    EQUIC_SOCKET_FINAL_SIZE = -13,
};

class IQuicStreamIter {
public:
    virtual bool next(uint64_t *stream_id) = 0;
    virtual ~IQuicStreamIter() {};
};

class QuicConnection {
public:
    ~QuicConnection();

    const std::vector<uint8_t> src_conn_id;

    ssize_t receive(uint8_t *buf, size_t buf_len);
    ssize_t send(uint8_t *buf, size_t buf_len);
    bool is_established();
    IQuicStreamIter *readable();
    ssize_t stream_receive(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool *finished);
    ssize_t stream_send(uint64_t stream_id, const uint8_t *buf, size_t buf_len, bool finished);
    uint64_t timeout_as_millis();
    void on_timeout();
    bool is_closed();

    static QuicConnection *accept(uint8_t *odcid, size_t odcid_len);


private:
    QuicConnection(quiche_conn *q_conn_, quiche_config *q_config_, std::vector<uint8_t> src_conn_id_);

    quiche_conn *q_conn;
    quiche_config *q_config;

    static quiche_config *generate_quiche_config();
};
