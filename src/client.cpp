#include "log.h"
#include "quic_client.h"

#include <unistd.h>

namespace {

const char *HOST = "127.0.0.1";
const char *PORT = "8080";
}

int main(int argc, char *argv[]) {
    QuicClient *client = new QuicClient(HOST, PORT);
    equic_client_t e;

    for (e = client->connect(); e == EQUIC_CLIENT_AGAIN; e = client->connect()) ;
    if (e != EQUIC_CLIENT_OK) {
        LOG_ERROR("client->connect() failed. %d", e);
        delete client;
        return -1;
    } else {
        LOG_DEBUG("connected.");
    }
    return 0;
}
