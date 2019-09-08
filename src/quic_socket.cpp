#include "quic_socket.h"
#include "quic_header_info.h"
#include "log.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/errno.h>

#define MAX_DATAGRAM_SIZE (1350)

class QuicStreamIter : public IQuicStreamIter {
public:
    QuicStreamIter(quiche_stream_iter *i);
    virtual ~QuicStreamIter();
    virtual bool next(uint64_t *stream_id);
private:
    quiche_stream_iter *iter;
};

QuicStreamIter::QuicStreamIter(quiche_stream_iter *i) : iter(i) {
}

QuicStreamIter::~QuicStreamIter() {
    if (iter) {
        quiche_stream_iter_free(iter);
    }
}

bool QuicStreamIter::next(uint64_t *stream_id) {
    return !!quiche_stream_iter_next(iter, stream_id);
}

QuicSocket::QuicSocket(quiche_conn *q_conn_, quiche_config *q_config_, std::vector<uint8_t> src_conn_id_)
    : q_conn(q_conn_)
    , q_config(q_config_)
    , src_conn_id(std::move(src_conn_id_)) {
}

QuicSocket::~QuicSocket() {
    quiche_conn_free(q_conn);
    quiche_config_free(q_config);
}

ssize_t QuicSocket::receive(uint8_t *buf, size_t buf_len) {
    return quiche_conn_recv(q_conn, buf, buf_len);
}

ssize_t QuicSocket::send(uint8_t *buf, size_t buf_len) {
    return quiche_conn_send(q_conn, buf, buf_len);
}

bool QuicSocket::is_established() {
    return !!quiche_conn_is_established(q_conn);
}

IQuicStreamIter *QuicSocket::readable() {
    quiche_stream_iter *iter = quiche_conn_readable(q_conn);
    if (!iter) {
        LOG_ERROR("quiche_conn_readable() failed().");
        return nullptr;
    }

    try {
        return new QuicStreamIter(iter);
    } catch(std::bad_alloc e) {
        LOG_ERROR("QuicStreamIter::QuicStreamIter failed. %s", e.what());
        quiche_stream_iter_free(iter);
        return nullptr;
    }
}

ssize_t QuicSocket::stream_receive(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool *finished) {
    return quiche_conn_stream_recv(q_conn, stream_id, buf, buf_len, finished);
}

ssize_t QuicSocket::stream_send(uint64_t stream_id, const uint8_t *buf, size_t buf_len, bool finished) {
    return quiche_conn_stream_send(q_conn, stream_id, buf, buf_len, finished);
}

uint64_t QuicSocket::timeout_as_nanos() {
    return quiche_conn_timeout_as_nanos(q_conn);
}

void QuicSocket::on_timeout() {
    quiche_conn_on_timeout(q_conn);
}

bool QuicSocket::is_closed() {
    return !!quiche_conn_is_closed(q_conn);
}

QuicSocket *QuicSocket::accept(uint8_t *odcid, size_t odcid_len) {
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        LOG_ERROR("open(/dev/urandom) failed. %d", errno);
        return nullptr;
    }

    uint8_t cid[LOCAL_CONN_ID_LEN] = {0};
    ssize_t rand_len = read(rng, cid, LOCAL_CONN_ID_LEN);
    if (rand_len < 0) {
        LOG_ERROR("read() failed. %d", errno);
        close(rng);
        return nullptr;
    }
    close(rng);

    quiche_config *config = QuicSocket::generate_quiche_config();
    if (!config) {
        LOG_ERROR("QuicSocket::generate_quiche_config() failed.");
        return nullptr;
    }

    quiche_conn *conn = quiche_accept(cid, LOCAL_CONN_ID_LEN, odcid, odcid_len, config);
    if (conn == NULL) {
        LOG_ERROR("quiche_accept() failed.");
        quiche_config_free(config);
        return nullptr;
    }

    std::vector<uint8_t> src_conn_id(cid, cid + LOCAL_CONN_ID_LEN);

    QuicSocket *qsock = nullptr;
    try {
        qsock = new QuicSocket(conn, config, std::move(src_conn_id));
    } catch(std::bad_alloc e) {
        LOG_ERROR("QuicSocket::QuicSocket failed. %s", e.what());
        quiche_config_free(config);
        return nullptr;
    }

    return qsock;
}

quiche_config *QuicSocket::generate_quiche_config() {
    quiche_config *config = NULL;

    if (!(config = quiche_config_new(QUICHE_PROTOCOL_VERSION))) {
        LOG_ERROR("quiche_config_new() faield.");
        goto error;
    } else if (quiche_config_load_cert_chain_from_pem_file(config, "cert.crt")) {
        LOG_ERROR("quiche_config_load_cert_chain_from_pem_file() failed.");
        goto error;
    } else if (quiche_config_load_priv_key_from_pem_file(config, "cert.key")) {
        LOG_ERROR("quiche_config_load_priv_key_from_pem_file() failed.");
        goto error;
    } else if (quiche_config_set_application_protos(config,
        (uint8_t *) "\x05hq-22\x08http/0.9", 15)) {
        LOG_ERROR("quiche_config_load_priv_key_from_pem_file() failed.");
        goto error;
    }

    quiche_config_set_idle_timeout(config, 5000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);

    return config;

error:
    if (config) {
        quiche_config_free(config);
    }
    return NULL;
}
