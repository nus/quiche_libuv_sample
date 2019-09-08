#pragma once

#include "udp_socket.h"

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

class QuicSocket {
public:
    ~QuicSocket();

    const std::vector<uint8_t> src_conn_id;

    ssize_t receive(uint8_t *buf, size_t buf_len);
    ssize_t send(uint8_t *buf, size_t buf_len);
    bool is_established();
    IQuicStreamIter *readable();
    ssize_t stream_receive(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool *finished);
    ssize_t stream_send(uint64_t stream_id, const uint8_t *buf, size_t buf_len, bool finished);
    uint64_t timeout_as_nanos();
    void on_timeout();
    bool is_closed();

    static QuicSocket *accept(uint8_t *odcid, size_t odcid_len, std::shared_ptr<UdpReceiveContext> context);


private:
    QuicSocket(quiche_conn *q_conn_, quiche_config *q_config_, std::vector<uint8_t> src_conn_id_,
               std::shared_ptr<UdpReceiveContext> context);

    quiche_conn *q_conn;
    quiche_config *q_config;
    const std::shared_ptr<UdpReceiveContext> context;

    static quiche_config *generate_quiche_config();
};
