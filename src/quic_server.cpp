#include "quic_server.h"
#include "quic_header_info.h"

#include "log.h"

#define MAX_DATAGRAM_SIZE (1350)

class ServerContext : public IQuicServerConnection{
public:
    ServerContext(QuicConnection *q, QuicServer *s, std::shared_ptr<UdpReceiveContext> urc, const std::vector<uint8_t> &c)
        : quic_socket(q)
        , quic_server(s)
        , udp_receive_context(urc)
        , connection_id(c)
        , is_on_connect_called(false) {}
    uv_timer_t timeout;
    QuicConnection *quic_socket;
    QuicServer *quic_server;
    std::shared_ptr<UdpReceiveContext> udp_receive_context;
    const std::vector<uint8_t> connection_id;
    bool is_on_connect_called;
    IQuicServerConnection *connection;

    virtual void stream_send(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool finish) {
        quic_socket->stream_send(stream_id, (const uint8_t *)buf, buf_len, finish);
    }

    virtual std::vector<uint8_t> get_connection_id() {
        return connection_id;
    }
};

static void LOG_CONNECTION_ID(const std::vector<uint8_t> &cid) {
    fprintf(stderr, "CONNECTIN_ID ");
    for (auto it = cid.begin(); it != cid.end(); it++) {
        fprintf(stderr, "%02x", *it);
    }

    fprintf(stderr, "\n");
}

static void debug_log(const char *line, void *argp) {
#if 0
    LOG_DEBUG("quiche-log %s", line);
#endif
}

QuicServer::QuicServer()
    : loop(uv_default_loop())
    , udp_socket(new UdpSocket(loop)) {
    quiche_enable_debug_logging(debug_log, NULL);
}

QuicServer::~QuicServer() {
    delete udp_socket;
}

void QuicServer::set_callback(IQuicServerCallback *callback_) {
    callback = callback_;
}

bool QuicServer::listen(const char *ip, int port) {
    udp_socket->bind(ip, port);
    udp_socket->start_receive(this, this);
    return true;
}

int QuicServer::run_loop() {
    return uv_run(loop, UV_RUN_DEFAULT);
}

void QuicServer::udp_socket_on_receive(ssize_t nread, uint8_t *buf, const struct sockaddr *addr, void *data, std::shared_ptr<UdpReceiveContext> context) {
    std::unique_ptr<QuicHeaderInfo> header_info = QuicHeaderInfo::parse(nread, buf);
    if (!header_info.get()) {
        LOG_ERROR("QuicHeaderInfo::parse() failed.");
        return;
    }

    LOG_DEBUG("version(0x%x) type(%u)", header_info->version, header_info->type);
    LOG_CONNECTION_ID(header_info->dst_conn_id);

    ServerContext *server_context = nullptr;
    QuicConnection *quic_socket = nullptr;
    auto it = quic_sockets.find(header_info->dst_conn_id);
    if (it != quic_sockets.end()) {
        server_context = it->second;
        quic_socket = server_context->quic_socket;
    }
    if (quic_socket == nullptr) {
        if (header_info->version != QUICHE_PROTOCOL_VERSION) {
            uint8_t out[MAX_DATAGRAM_SIZE];
            size_t out_len = MAX_DATAGRAM_SIZE;
            LOG_DEBUG("version negotiation");
            if (!quic_version_packet(header_info->src_conn_id, header_info->dst_conn_id, out, &out_len)) {
                LOG_ERROR("quic_version_packet() failed.");
                return;
            }

            udp_socket->send(out, out_len, context);
            return; 
        }
        if (header_info->token.size() == 0) {
            socklen_t peer_addr_len = sizeof(*addr);
            std::vector<uint8_t> token;
            uint8_t out[MAX_DATAGRAM_SIZE];
            size_t out_len = MAX_DATAGRAM_SIZE;

            if (!quic_mint_token(header_info->dst_conn_id, addr, peer_addr_len, token)) {
                LOG_ERROR("quic_mint_token() failed.");
                return;
            } else if (!quic_retry_packet(header_info->src_conn_id, header_info->dst_conn_id, header_info->dst_conn_id, token, out, &out_len)) {
                LOG_ERROR("quic_retry_packet() failed.");
                return;
            }

            udp_socket->send(out, out_len, context);
            return;
        }

        const struct sockaddr_storage *addr_storage = reinterpret_cast<const struct sockaddr_storage *>(addr);
        socklen_t peer_addr_len = sizeof(*addr);
        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        if (!quic_validate_token(header_info->token, addr_storage, peer_addr_len, odcid, &odcid_len)) {
            LOG_ERROR("quic_validate_token() failed.");
            return;
        }

        quic_socket = create_quic_socket(odcid, odcid_len, context);
        if (!quic_socket) {
            LOG_ERROR("create_quic_socket() failed.");
            return;
        }
    }

    ssize_t done = quic_socket->receive(buf, nread);
    if (done == EQUIC_SOCKET_DONE) {
        LOG_DEBUG("quic_socket->receive() done.");
        return;
    } else if (done < 0) {
        LOG_ERROR("quic_socket->receive() failed. %ld", done);
        return;
    }

    if (quic_socket->is_established()) {
        LOG_DEBUG("is_established.");
        if (callback && !server_context->is_on_connect_called) {
            callback->on_connect(server_context);
            server_context->is_on_connect_called = true;
        }

        uint64_t stream_id = 0;
        IQuicStreamIter *iter = quic_socket->readable();
        if (iter) {
            while (iter->next(&stream_id)) {
                LOG_DEBUG("stream %lld is readable.", stream_id);

                uint8_t b[1024] = {0};
                bool finished = false;
                ssize_t recv_len = quic_socket->stream_receive(stream_id, b, sizeof(b), &finished);
                if (recv_len < 0) {
                    break;
                }
                LOG_DEBUG("received %zd, %s", recv_len, b);
                if (callback) {
                    callback->on_receive(server_context, stream_id, b, recv_len, finished);
                }
            }
            delete iter;
        }
    }

    for (auto it = quic_sockets.begin(); it != quic_sockets.end(); it++) {
        LOG_CONNECTION_ID(it->first);

        ServerContext *server_context = it->second;
        QuicConnection *quic_socket = server_context->quic_socket;
        flush_egress(quic_socket, context);
        restart_timer(server_context);

        if (quic_socket->is_closed()) {
            if (callback) {
                callback->on_disconnect(server_context);
            }

            quic_sockets.erase(it);

            uv_timer_stop(&server_context->timeout);

            delete quic_socket;
            delete server_context;
        }
    }
}

void QuicServer::udp_socket_on_send(void *data) {

}

bool QuicServer::quic_version_packet(std::vector<uint8_t> src_conn_id, std::vector<uint8_t> dst_conn_id, uint8_t *out, size_t *out_len) {
    ssize_t written = quiche_negotiate_version(&src_conn_id[0], src_conn_id.size(),
                                               &dst_conn_id[0], dst_conn_id.size(),
                                               out, *out_len);
    if (written < 0) {
        LOG_ERROR("quiche_negotiate_version() failed. %zd", written);
        return false;
    }

    *out_len = written;
    return true;
}

bool QuicServer::quic_retry_packet(const std::vector<uint8_t> &src_conn_id,
                                   const std::vector<uint8_t> &dst_conn_id,
                                   const std::vector<uint8_t> &new_src_conn_id,
                                   const std::vector<uint8_t> &token,
                                   uint8_t *out, size_t *out_len) {
    ssize_t written = quiche_retry(&src_conn_id[0], src_conn_id.size(),
                                   &dst_conn_id[0], dst_conn_id.size(),
                                   &new_src_conn_id[0], new_src_conn_id.size(),
                                   &token[0], token.size(),
                                   out, *out_len);
    if (written < 0) {
        LOG_ERROR("quiche_retry() failed. %zd", written);
        return false;
    }

    *out_len = written;
    return true;
}

bool QuicServer::quic_validate_token(const std::vector<uint8_t> &token_,
                                     const struct sockaddr_storage *addr, socklen_t addr_len,
                                     uint8_t *odcid, size_t *odcid_len) {
    const uint8_t *token = &token_[0];
    size_t token_len = token_.size();
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

bool QuicServer::quic_mint_token(const std::vector<uint8_t> &dst_conn_id, const struct sockaddr *addr, socklen_t addr_len, std::vector<uint8_t> &token) {
    size_t token_len = sizeof("quiche") - 1 + addr_len + dst_conn_id.size();
    token.resize(token_len);

    memcpy(&token[0], "quiche", sizeof("quiche") - 1);
    memcpy(&token[0] + sizeof("quiche") - 1, addr, addr_len);
    memcpy(&token[0] + sizeof("quiche") - 1 + addr_len, &dst_conn_id[0], dst_conn_id.size());

    return true;
}

QuicConnection *QuicServer::create_quic_socket(uint8_t *odcid, size_t odcid_len, std::shared_ptr<UdpReceiveContext> context) {
    QuicConnection *qsock = QuicConnection::accept(odcid, odcid_len);
    if (!qsock) {
        LOG_ERROR("QuickSocket::accept() failed.");
        return nullptr;
    }

    LOG_DEBUG("accepted.");

    ServerContext *server_context = new ServerContext(qsock, this, context, qsock->src_conn_id);

    uv_timer_init(loop, &server_context->timeout);
    server_context->timeout.data = server_context;
    uv_timer_start(&server_context->timeout, timeout_callback, 1000, 0);

    quic_sockets[qsock->src_conn_id] = server_context;
    LOG_CONNECTION_ID(qsock->src_conn_id);

    return qsock;
}

void QuicServer::restart_timer(ServerContext *server_context) {
    uint64_t millis = server_context->quic_socket->timeout_as_millis();
    LOG_DEBUG("restart_timer: %llu", millis);
    uv_timer_set_repeat(&server_context->timeout, millis);
    uv_timer_again(&server_context->timeout);
}

bool QuicServer::flush_egress(QuicConnection *quic_socket, std::shared_ptr<UdpReceiveContext> context) {
    if (!quic_socket) {
        LOG_ERROR("quic_socket must be not null.");
        return false;
    }

    while (1) {
        uint8_t out[MAX_DATAGRAM_SIZE];
        ssize_t written = quic_socket->send(out, sizeof(out));
        if (written == EQUIC_SOCKET_DONE) {
            LOG_DEBUG("quic_socket->send() done.");
            break;
        } else if (written < 0) {
            LOG_ERROR("quic_socket->send() failed. %ld", written);
            return false;
        }

        udp_socket->send(out, written, context);
    }

    return true;
}

void QuicServer::timeout_callback(uv_timer_t *timer) {
    ServerContext *server_context = reinterpret_cast<ServerContext*>(timer->data);
    QuicConnection *quic_socket = server_context->quic_socket;
    QuicServer *quic_server = server_context->quic_server;

    LOG_DEBUG("timeout_callback called.");

    quic_socket->on_timeout();

    quic_server->flush_egress(quic_socket, server_context->udp_receive_context);
    quic_server->restart_timer(server_context);

    if (quic_socket->is_closed()) {
        LOG_CONNECTION_ID(server_context->connection_id);
        quic_server->quic_sockets.erase(server_context->connection_id);

        uv_timer_stop(&server_context->timeout);

        if (quic_server->callback) {
            quic_server->callback->on_disconnect(server_context);
        }

        delete quic_socket;
        delete server_context;
    }
}
