#include "log.h"
#include "quic_client.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <thread>
#include <chrono>

namespace {

void sleep_for(ssize_t millis) {
    std::this_thread::sleep_for(std::chrono::milliseconds(millis));
}

static off_t read_file(const char *path, char **buffer) {
    int fd = -1;
    FILE *fp = 0;
    struct stat stbuf;
    char *buf = NULL;

    if ((fd = open(path, O_RDONLY)) == 1) {
        fprintf(stderr, "open(%s) failed: %d\n", path, errno);
        goto err;
    } else if (fstat(fd, &stbuf) == -1) {
        fprintf(stderr, "fstat() failed: %d\n", errno);
        goto err;
    } else if (!(fp = fdopen(fd, "r"))) {
        fprintf(stderr, "fdopen() failed: %d\n", errno);
        goto err;
    } else if (!(buf = (char *) calloc(1, stbuf.st_size))) {
        fprintf(stderr, "calloc() failed.\n");
        goto err;
    } else if ((fread(buf, sizeof(char), stbuf.st_size, fp)) != stbuf.st_size) {
        fprintf(stderr, "fread() failed.\n");
        goto err;
    } else {
        *buffer = buf;
        return stbuf.st_size;
    }

err:
    if (buf) free(buf);
    if (fp) fclose(fp);
    if (fd == -1) close(fd);

    return -1;
}

}

int main(int argc, char *argv[]) {
    ssize_t buf_len;
    char *buf;

    if (argc < 4) {
        LOG_ERROR("Set arguments: %s <host> <port> <file_to_upload>", argv[0]);
        return -1;
    } else if ((buf_len = read_file(argv[3], &buf)) < 0) {
        LOG_ERROR("read_file(%s) failed", argv[3]);
        return -1;
    }
    
    QuicClient *client = new QuicClient(argv[1], argv[2]);
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
    size_t payload_len = 65535;
    int cur = 0;
    while ((e = client->progress_while_connected()) == EQUIC_CLIENT_AGAIN) {
        sleep_for(1);

        if (!req_sent) {
            bool fin = (buf_len - cur) <= payload_len;
            int len = fin ? (buf_len - cur) : payload_len;
            cur += client->stream_send(4, (uint8_t *) buf, len, fin);

            if (fin) {
                req_sent = true;
            }
            printf("cur: %d\n", cur);
        } else {
            IQuicClientStreamIter *iter = client->readable();
            if (iter) {
                uint64_t stream_id = 0;
                while (iter->next(&stream_id)) {
                    LOG_DEBUG("stream %" PRIx64 " is readable.", stream_id);

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
