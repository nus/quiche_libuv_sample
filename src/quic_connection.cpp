#include "quic_connection.h"
#include "quic_header_info.h"
#include "log.h"

#include <memory.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/errno.h>

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

QuicConnection::QuicConnection(quiche_conn *q_conn_, quiche_config *q_config_, std::vector<uint8_t> src_conn_id_)
    : q_conn(q_conn_)
    , q_config(q_config_)
    , src_conn_id(std::move(src_conn_id_)) {
}

QuicConnection::~QuicConnection() {
    quiche_conn_free(q_conn);
    quiche_config_free(q_config);
}

ssize_t QuicConnection::receive(uint8_t *buf, size_t buf_len) {
    return quiche_conn_recv(q_conn, buf, buf_len);
}

ssize_t QuicConnection::send(uint8_t *buf, size_t buf_len) {
    return quiche_conn_send(q_conn, buf, buf_len);
}

bool QuicConnection::is_established() {
    return !!quiche_conn_is_established(q_conn);
}

bool QuicConnection::application_protocol(const uint8_t **out, size_t *out_len) {
    if (!out) {
        LOG_ERROR("out must be not null.");
        return false;
    } else if (*out) {
        LOG_ERROR("*out must be null.");
        return false;
    } else if (!out_len) {
        LOG_ERROR("out_len must be not null.");
        return false;
    }

    quiche_conn_application_proto(q_conn, out, out_len);

    return true;
}

IQuicStreamIter *QuicConnection::readable() {
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

ssize_t QuicConnection::stream_receive(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool *finished) {
    return quiche_conn_stream_recv(q_conn, stream_id, buf, buf_len, finished);
}

ssize_t QuicConnection::stream_send(uint64_t stream_id, const uint8_t *buf, size_t buf_len, bool finished) {
    return quiche_conn_stream_send(q_conn, stream_id, buf, buf_len, finished);
}

int QuicConnection::close(bool app, uint64_t err, const uint8_t *reason, size_t reason_len) {
    return quiche_conn_close(q_conn, app, err, reason, reason_len);
}

uint64_t QuicConnection::timeout_as_millis() {
    return quiche_conn_timeout_as_millis(q_conn);
}

void QuicConnection::on_timeout() {
    quiche_conn_on_timeout(q_conn);
}

bool QuicConnection::is_closed() {
    return !!quiche_conn_is_closed(q_conn);
}

void QuicConnection::stats(QuicConnectionStats *s) {
    quiche_stats qs;
    quiche_conn_stats(q_conn, &qs);

    s->recv = qs.recv;
    s->sent = qs.sent;
    s->lost = qs.lost;
    s->rtt = qs.rtt;
    s->cwnd = qs.cwnd;
}

QuicConnection *QuicConnection::accept(uint8_t *odcid, size_t odcid_len) {
    uint8_t cid[LOCAL_CONN_ID_LEN] = {0};
    if (!generate_connection_id(cid, LOCAL_CONN_ID_LEN)) {
        LOG_ERROR("QuicConnection::generate_connection_id() failed.");
        return nullptr;
    }

    quiche_config *config = QuicConnection::generate_quiche_server_config();
    if (!config) {
        LOG_ERROR("QuicConnection::generate_quiche_server_config() failed.");
        return nullptr;
    }

    quiche_conn *conn = quiche_accept(cid, LOCAL_CONN_ID_LEN, odcid, odcid_len, config);
    if (conn == NULL) {
        LOG_ERROR("quiche_accept() failed.");
        quiche_config_free(config);
        return nullptr;
    }

    std::vector<uint8_t> src_conn_id(cid, cid + LOCAL_CONN_ID_LEN);

    try {
        return new QuicConnection(conn, config, std::move(src_conn_id));
    } catch(std::bad_alloc e) {
        LOG_ERROR("QuicConnection::QuicConnection failed. %s", e.what());
        quiche_conn_free(conn);
        quiche_config_free(config);
        return nullptr;
    }
}

QuicConnection *QuicConnection::connect(const char *host) {
    uint8_t scid[LOCAL_CONN_ID_LEN];

    if (!generate_connection_id(scid, LOCAL_CONN_ID_LEN)) {
        LOG_ERROR("QuicConnection::generate_connection_id() failed.");
        return nullptr;
    }

    LOG_CONNECTION_ID(LOG_LEVEL_DEBUG, std::vector<uint8_t>(scid, scid + LOCAL_CONN_ID_LEN));

    quiche_config *config = QuicConnection::generate_quiche_client_config();
    if (!config) {
        LOG_ERROR("QuicConnection::generate_quiche_client_config() failed.");
        return nullptr;
    }

    quiche_conn *conn = quiche_connect(host, (const uint8_t *) scid,
                                       sizeof(scid), config);
    if (conn == NULL) {
        LOG_ERROR("quiche_connect() failed.");
        quiche_config_free(config);
        return nullptr;
    }

    std::vector<uint8_t> src_conn_id(scid, scid + LOCAL_CONN_ID_LEN);

    try {
        return new QuicConnection(conn, config, std::move(src_conn_id));
    } catch(std::bad_alloc e) {
        LOG_ERROR("QuicConnection::QuicConnection failed. %s", e.what());
        quiche_conn_free(conn);
        quiche_config_free(config);
        return nullptr;
    }
}

quiche_config *QuicConnection::generate_quiche_server_config() {
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
    quiche_config_set_initial_max_stream_data_bidi_local(config, 100000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 100000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);

    return config;

error:
    if (config) {
        quiche_config_free(config);
    }
    return NULL;
}

quiche_config *QuicConnection::generate_quiche_client_config() {
    quiche_config *config = NULL;

    if (!(config = quiche_config_new(QUICHE_PROTOCOL_VERSION))) {
        LOG_ERROR("quiche_config_new() faield.");
        goto error;
    } else if (quiche_config_set_application_protos(config,
        (uint8_t *) "\x05hq-22\x08http/0.9", 15)) {
        LOG_ERROR("quiche_config_load_priv_key_from_pem_file() failed.");
        goto error;
    }

    quiche_config_set_idle_timeout(config, 5000);
    quiche_config_set_max_packet_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 100000000);
    quiche_config_set_initial_max_stream_data_uni(config, 100000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true); // TODO Set false to enable connection migration.

    return config;

error:
    if (config) {
        quiche_config_free(config);
    }
    return NULL;
}

bool QuicConnection::generate_connection_id(uint8_t *buf, size_t buf_len) {
    memset(buf, 0, buf_len);

    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        LOG_ERROR("open(/dev/urandom) failed. %d", errno);
        return false;
    }

    ssize_t rand_len = read(rng, buf, buf_len);
    if (rand_len < 0) {
        LOG_ERROR("read() failed. %d", errno);
        ::close(rng);
        return false;
    }
    ::close(rng);

    return true;
}
