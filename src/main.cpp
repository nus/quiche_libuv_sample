#include "udp_socket.h"
#include "quic_socket.h"
#include "log.h"

#include "quic_server.h"


int main(int argc, char *argv[]) {
    QuicServer server;

    if (!server.listen("0.0.0.0", 8080)) {
        LOG_ERROR("server.bind() failed.");
        return 1;
    }

    server.run_loop();

    return 0;
}
