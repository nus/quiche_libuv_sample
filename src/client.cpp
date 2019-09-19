#include "log.h"
#include "quic_client.h"

#include <unistd.h>
#include <thread>
#include <chrono>

namespace {

const char *HOST = "127.0.0.1";
const char *PORT = "8080";

void sleep_for(ssize_t millis) {
    std::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

}

int main(int argc, char *argv[]) {
    QuicClient *client = new QuicClient(HOST, PORT);
    equic_client_t e;

    for (e = client->connect(); e == EQUIC_CLIENT_AGAIN; e = client->connect()) {
        sleep_for(30);
    }
    if (e != EQUIC_CLIENT_OK) {
        LOG_ERROR("client->connect() failed. %d", e);
        delete client;
        return -1;
    }
    LOG_DEBUG("connected to host.");

    bool req_sent = false;
    while ((e = client->progress_while_connected()) == EQUIC_CLIENT_AGAIN) {
        sleep_for(30);

        if (!req_sent) {
            const uint8_t r[] = "GET /index.html\r\n";
            client->stream_send(4, r, sizeof(r), true);
            req_sent = true;
        } else {
            IQuicClientStreamIter *iter = client->readable();
            if (iter) {
                uint64_t stream_id = 0;
                while (iter->next(&stream_id)) {
                    LOG_DEBUG("stream %lld is readable.", stream_id);

                    uint8_t buf[1024] = {0};
                    bool finished = false;
                    ssize_t recv_len = client->stream_receive(stream_id, buf, sizeof(buf), &finished);
                    if (recv_len < 0) {
                        break;
                    }

                    LOG_DEBUG("received %.*s", (int) recv_len, buf);
                    if (finished) {
                        LOG_DEBUG("finished!");
                        if (client->close(true, 0, NULL, 0) < 0) {
                            LOG_ERROR("client->close() failed.");
                        }
                    }
                }
                delete iter;
            }
        }

        if (!client->flush_egress()) {
            LOG_ERROR("client->flush_egress() failed.");
            break;
        }
    }

    delete client;

    return 0;
}
