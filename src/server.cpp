#include "udp_socket.h"
#include "quic_connection.h"
#include "log.h"

#include "quic_server.h"

#include <inttypes.h>
#include <string>

namespace {

class ConnectionPair {
public:
    IQuicServerConnection *alice;
    IQuicServerConnection *bob;

    bool send_to_peer(IQuicServerConnection *connection, uint64_t stream_id, uint8_t *buf, size_t buf_len, bool finished) {
        if (connection == alice) {
            if (!bob) {
                LOG_ERROR("None bob.");
                return false;
            }
            bob->stream_send(stream_id, buf, buf_len, finished);
            return true;
        } else if (connection == bob) {
            if (!alice) {
                LOG_ERROR("None alice.");
                return false;
            }
            alice->stream_send(stream_id, buf, buf_len, finished);
            return true;
        } else {
            LOG_ERROR("Who are you?!");
            return false;
        }
    }
};

class ConnectionPairContainer {
public:
    void regist(IQuicServerConnection* connection, const char *channel) {
        ConnectionPair *pair;
        std::string chan(channel);

        auto conn = table.find(chan);
        bool unregistered = conn == table.end();
        if (unregistered) {
            pair = new ConnectionPair();
            pair->alice = connection;
            table[chan] = pair;
        } else {
            pair = conn->second;
            pair->bob = connection;
        }
    }

    void unregist(IQuicServerConnection* connection, const char *channel) {
        std::string chan(channel);

        auto conn = table.find(chan);
        bool registered = conn != table.end();
        if (registered) {
            ConnectionPair *pair = conn->second;
            if (pair->alice == connection) {
                pair->alice = nullptr;
            } else {
                pair->bob = nullptr;
            }

            if ((!pair->alice) && (!pair->bob)) {
                table.erase(conn);
            }
        }
    }

    ConnectionPair *find_connection_pair(IQuicServerConnection *peer) {
        for (auto it = table.begin(); it != table.end(); it++) {
            ConnectionPair *conn = it->second;
            if (!conn) {
                continue;
            } else if (conn->alice == peer) {
                return conn;
            } else if (conn->bob == peer) {
                return conn;
            }
        }
        return nullptr;
    }

private:
    std::map<std::string, ConnectionPair *> table;
};

class Callback : public IQuicServerCallback {
    int n;
    virtual void on_connect(IQuicServerConnection *connection) {
        LOG_DEBUG("on_connect");
        n = 0;
    }
    virtual void on_receive(IQuicServerConnection *connection, uint64_t stream_id, uint8_t *buf, size_t buf_len, bool finished) {
        n += buf_len;
        LOG_DEBUG("on_receive stream_id:%" PRIx64 " buf_len:%zu, n:%d", stream_id, buf_len, n);
        printf("%.*s", (int) buf_len, buf);

        if (finished) {
            char resp[] = "byez!\n";
            connection->stream_send(stream_id, (uint8_t *)resp, sizeof(resp), true);
            fprintf(stderr, "byez send.\n");
        }
    }
    virtual void on_disconnect(IQuicServerConnection *connection) {
        LOG_DEBUG("on_disconnect");

        fflush(stdout);
    }
};

} // namespace

int main(int argc, char *argv[]) {
    QuicServer server;

    server.set_callback(new Callback());

    if (!server.listen("0.0.0.0", 8080)) {
        LOG_ERROR("server.bind() failed.");
        return 1;
    }

    server.run_loop();

    return 0;
}
