#include "quic_client.h"
#include "log.h"

#include <unistd.h>

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
        close(sock);
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
        const struct addrinfo hints = {
            .ai_family = PF_UNSPEC,
            .ai_socktype = SOCK_DGRAM,
            .ai_protocol = IPPROTO_UDP
        };
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
                // Succeeded to create a socket.
                freeaddrinfo(peer);
                return EQUIC_CLIENT_AGAIN;
            }
        }


error:
        if (s != -1) {
            close(s);
        }
        if (peer) {
            freeaddrinfo(peer);
        }
        if (quic_connection) {
            delete quic_connection;
        }
        return EQUIC_CLIENT_INTERNAL;
    } else {
        uint8_t buf[65535];
        ssize_t read;
        ssize_t done;
        
        if ((read = ::recv(sock, buf, sizeof(buf), 0)) < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                return EQUIC_CLIENT_AGAIN;
            } else {
                return EQUIC_CLIENT_INTERNAL;
            }
        } else if ((done = quic_connection->receive(buf, read)) == EQUIC_SOCKET_DONE) {
            /* Succeeded to connect on QUIC. */
            return EQUIC_CLIENT_OK;
        } else if (done < 0) {
            LOG_ERROR("quic_connection->receive() failed.");
            return EQUIC_CLIENT_INTERNAL;
        } else if (quic_connection->is_closed()) {
            LOG_ERROR("The QUIC connection is closed while connectiong.");
            return EQUIC_CLIENT_CLOSED;
        } else {
            return EQUIC_CLIENT_AGAIN;
        }
    }
}

bool QuicClient::flush_egress() {
    uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        ssize_t written = quic_connection->send(out, sizeof(out));

        if (written == QUICHE_ERR_DONE) {
            LOG_DEBUG("quic_socket->send() done.");
            break;
        } else if (written < 0) {
            LOG_ERROR("quic_socket->send() failed. %ld", written);
            return false;
        }

        ssize_t sent = send(sock, out, written, 0);
        if (sent != written) {
            LOG_ERROR("send() failed. %d", errno);
            return false;
        }
    }

    // TOOD restart timeout timer.

    return true;
}
