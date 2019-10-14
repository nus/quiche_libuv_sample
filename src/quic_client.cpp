#include "quic_client.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace {
class QuicClientStreamIter : public IQuicClientStreamIter {
public:
    QuicClientStreamIter(IQuicStreamIter *iter_)
        : iter(iter_) {}
    ~QuicClientStreamIter() {
        delete iter;
    }
    virtual bool next(uint64_t *stream_id) {
        return iter->next(stream_id);
    }
private:
    IQuicStreamIter *iter;
};

}

QuicClient::QuicClient(const char *host_, const char *port_)
    : sock(-1)
    , host(strdup(host_))
    , port(strdup(port_))
    , quic_connection(nullptr) {
    LOG_DEBUG("QuicClient() called.");
}

QuicClient::~QuicClient() {
    LOG_DEBUG("~QuicClient() called.");
    if (quic_connection) {
        delete quic_connection;
    }
    if (sock != -1) {
        ::close(sock);
    }
    if (host) {
        free(host);
    }
    if (port) {
        free(port);
    }
}

equic_client_t QuicClient::connect() {
    if (sock == -1) {
        struct addrinfo hints = {0};
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        struct addrinfo *peer = nullptr;
        int s = -1;
        QuicConnection *q = nullptr;

        if (getaddrinfo(host, port, &hints, &peer) != 0) {
            LOG_ERROR("getaddrinfo failed. %d", errno);
            goto error;
        } else if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            LOG_ERROR("socket failed. %d", errno);
            goto error;
        } else if (fcntl(s, F_SETFL, O_NONBLOCK) != 0) {
            LOG_ERROR("fcntl() failed. %d", errno);
            goto error;
        } else if (::connect(s, peer->ai_addr, peer->ai_addrlen) < 0) {
            LOG_ERROR("connect() failed. %d", errno);
            goto error;
        } else if (!(q = QuicConnection::connect(host))) {
            LOG_ERROR("QuicConnection::connect() failed.");
            goto error;
        } else {
            sock = s;
            quic_connection = q;

            if (!flush_egress()) {
                LOG_ERROR("flush_egress() failed.");
                sock = -1;
                quic_connection = nullptr;
                goto error;
            } else {
                // Succeeded to create a UDP socket.
                freeaddrinfo(peer);
                return EQUIC_CLIENT_AGAIN;
            }
        }

error:
        if (s != -1) {
            ::close(s);
        }
        if (peer) {
            freeaddrinfo(peer);
        }
        if (quic_connection) {
            delete quic_connection;
        }
        return EQUIC_CLIENT_INTERNAL;
    } else if (quic_connection) {
        equic_client_t e = progress_while_connecting();
        if (e == EQUIC_CLIENT_OK) {
            // Succeeded to connect.
            const uint8_t *app_proto = nullptr;
            size_t app_proto_len = 0;

            if (quic_connection->application_protocol(&app_proto, &app_proto_len)) {
                LOG_DEBUG("Application protocol is %.*s", (int) app_proto_len, app_proto);
            } else {
                LOG_ERROR("quic_connection->application_protocol() failed.");
            }
        }

        return e;
    } else {
        LOG_ERROR("quic_connection must be not null.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    }
}


equic_client_t QuicClient::progress_while_connected() {
    if (sock == -1) {
        LOG_ERROR("sock must be created. Call connect() method.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    } else if (!quic_connection) {
        LOG_ERROR("quic_connection must be not null. Call connect() method.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    } else if (quic_connection->timeout_as_millis() == 0) {
        return EQUIC_CLIENT_ILLEGAL_TIMEOUT;
    }

    uint8_t buf[65535];
    ssize_t read;
    ssize_t done;

    if ((read = ::recv(sock, buf, sizeof(buf), 0)) < 0) {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
            goto received;
        } else {
            return EQUIC_CLIENT_INTERNAL;
        }
    } else if ((done = quic_connection->receive(buf, read)) == EQUIC_CONNECTION_DONE) {
        goto received;
    } else if (done < 0) {
        LOG_ERROR("quic_connection->receive() failed.");
        return EQUIC_CLIENT_INTERNAL;
    } else {
        return EQUIC_CLIENT_AGAIN;
    }

received:
    if (quic_connection->is_closed()) {
        LOG_ERROR("The QUIC connection is closed.");
        return EQUIC_CLIENT_CLOSED;
    } else if (!quic_connection->is_established()) {
        LOG_ERROR("The QUIC connection is not established.");
        return EQUIC_CLIENT_CLOSED;
    } else {
        return EQUIC_CLIENT_AGAIN;
    }
}

equic_client_t QuicClient::progress_while_connecting() {
    if (sock == -1) {
        LOG_ERROR("sock must be created. Call connect() method.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    } else if (!quic_connection) {
        LOG_ERROR("quic_connection must be not null. Call connect() method.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    }

    uint8_t buf[65535];
    ssize_t read;
    ssize_t done;

    if ((read = ::recv(sock, buf, sizeof(buf), 0)) < 0) {
        if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
            goto received;
        } else {
            return EQUIC_CLIENT_INTERNAL;
        }
    } else if ((done = quic_connection->receive(buf, read)) == EQUIC_CONNECTION_DONE) {
        goto received;
    } else if (done < 0) {
        LOG_ERROR("quic_connection->receive() failed.");
        return EQUIC_CLIENT_INTERNAL;
    } else {
        return EQUIC_CLIENT_AGAIN;
    }

received:
    if (quic_connection->is_closed()) {
        LOG_ERROR("The QUIC connection is closed while connectiong.");
        return EQUIC_CLIENT_CLOSED;
    } else if (quic_connection->is_established()) {
        return EQUIC_CLIENT_OK;
    } else if (!flush_egress()) {
        LOG_ERROR("flush_egress() failed.");
        return EQUIC_CLIENT_INTERNAL;
    } else {
        return EQUIC_CLIENT_AGAIN;
    }
}

ssize_t QuicClient::stream_send(uint64_t stream_id, const uint8_t *buf, size_t buf_len, bool finished) {
    if (!quic_connection->is_established()) {
        LOG_ERROR("quic_connection is not established.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    }

    ssize_t n = quic_connection->stream_send(stream_id, buf, buf_len, finished);
    if (n < 0) {
        LOG_ERROR("quic_connection->stream_send() failed.");
        return EQUIC_CLIENT_INTERNAL;
    }
    return n;

    return EQUIC_CLIENT_OK;
}

ssize_t QuicClient::stream_receive(uint64_t stream_id, uint8_t *buf, size_t buf_len, bool *finished) {
    if (!quic_connection->is_established()) {
        LOG_ERROR("quic_connection is not established.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    }

    return quic_connection->stream_receive(stream_id, buf, buf_len, finished);
}

IQuicClientStreamIter *QuicClient::readable() {
    IQuicStreamIter *iter = quic_connection->readable();
    if (!iter) {
        LOG_ERROR("quic_connection->readable() failed.");
        return nullptr;
    }
    return new QuicClientStreamIter(iter);
}


bool QuicClient::flush_egress() {
    uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        ssize_t written = quic_connection->send(out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            break;
        } else if (written < 0) {
            LOG_ERROR("quic_socket->send() failed. %ld", written);
            return false;
        }

        ssize_t sent = ::send(sock, out, written, 0);
        if (sent != written) {
            LOG_ERROR("send() failed. %d", errno);
            return false;
        }
        LOG_DEBUG("::send() %zd", sent);
    }

    // TOOD restart timeout timer.

    return true;
}

equic_client_t QuicClient::close(bool app, uint64_t err, const uint8_t *reason, size_t reason_len) {
    if (!quic_connection->is_established()) {
        LOG_ERROR("quic_connection is not established.");
        return EQUIC_CLIENT_ILLEGAL_STATUS;
    } 

   if (quic_connection->close(app, err, reason, reason_len) < 0) {
       LOG_ERROR("quic_connectio->close() failed.");
       return EQUIC_CLIENT_INTERNAL;
   } else {
       return EQUIC_CLIENT_OK;
   }
}
