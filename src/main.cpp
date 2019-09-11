#include "udp_socket.h"
#include "quic_socket.h"
#include "log.h"

#include "quic_server.h"

namespace {

class Callback : public IQuicServerCallback {
    virtual void on_connect(IQuicServerConnection *connection) {
        LOG_DEBUG("on_connect");
    }
    virtual void on_receive(IQuicServerConnection *connection, uint64_t stream_id, uint8_t *buf, size_t buf_len, bool finished) {
        LOG_DEBUG("on_receive stream_id:%llu buf_len:%zu", stream_id, buf_len);

        char resp[] = "byez!\n";
        connection->stream_send(stream_id, (uint8_t *)resp, sizeof(resp), true);
    }
    virtual void on_disconnect(IQuicServerConnection *connection) {
        LOG_DEBUG("on_disconnect");
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
