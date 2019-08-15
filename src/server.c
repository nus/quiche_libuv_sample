#include <stdio.h>
#include <quiche.h>
#include <uv.h>
#include <uthash.h>
#include <stdlib.h>

#if 1
#define DEBUG_LOG_FOR_QUICHE
#endif

#define LOG_DEBUG(FORMAT, ...) fprintf(stderr, "LOG_DEBUG "FORMAT"\n", ## __VA_ARGS__)
#define LOG_ERROR(FORMAT, ...) fprintf(stderr, "LOG_ERROR "FORMAT"\n", ## __VA_ARGS__)

#define MAX_DATAGRAM_SIZE (1350)

typedef struct {
    UT_hash_handle hash_handle;
} connection_t;

typedef struct {
    quiche_config *config;

    /* key: Destination Connection ID(char *), value: connection_t */
    connection_t *connections;
} server_context_t;

static void on_send() {
}

static void on_read(uv_udp_t *request, ssize_t nread, const uv_buf_t *buf, const struct sockaddr *addr, unsigned flags) {
    fprintf(stderr, "on_read, %zd, %u\n", nread, flags);
    if (nread < 0) {
        fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        uv_close((uv_handle_t*) request, NULL);
        fprintf(stderr, "free0 0x%p\n", buf->base);
        free(buf->base);
        return;
    } else if (addr == NULL) {
        fprintf(stderr, "free1 0x%p\n", buf->base);
        free(buf->base);
        return;
    }

    char sender[17] = {0};
    uv_ip4_name((const struct sockaddr_in*) addr, sender, 16);
    fprintf(stderr, "Recv from %s\n", sender);

    {
        server_context_t *server_context = (server_context_t *) request->data;
        connection_t *connection = NULL;

        const int LOCAL_CONN_ID_LEN = 16;
        const int MAX_TOKEN_LEN = sizeof("quiche") - 1 +
                                  sizeof(struct sockaddr_storage) +
                                  QUICHE_MAX_CONN_ID_LEN;

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf->base, nread, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            LOG_ERROR("failed to parse header: %d\n", rc);
            free(buf->base);
            return;
        }

        LOG_DEBUG("version(0x%x) type(%u)", version, type);

        HASH_FIND(hash_handle, server_context->connections, dcid, dcid_len, connection);
        if (connection == NULL) {
            LOG_DEBUG("New connection");
            if (version != QUICHE_PROTOCOL_VERSION) {
                static uint8_t out[MAX_DATAGRAM_SIZE];
                LOG_DEBUG("version negotiation");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));
                if (written < 0) {
                    LOG_ERROR("failed to create vneg packet: %zd", written);
                    free(buf->base);
                    return;
                }

                uv_udp_send_t *send;
                uv_buf_t uv_buf;
                send = malloc(sizeof(*send));
                uv_buf = uv_buf_init(out, written);
                uv_udp_send(send, request, (const struct uv_buf_t *)&uv_buf, 1, (const struct sockaddr *)addr, on_send);
                free(buf->base);
                return;
            }
        }
    }
}

static void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *tmp = (char*) malloc(suggested_size);
    *buf = uv_buf_init(tmp, suggested_size);
}

#ifdef DEBUG_LOG_FOR_QUICHE
static void quiche_debug_log(const char *line, void *argp) {
    LOG_DEBUG("QUICHELOG: %s\n", line);
}
#endif

static quiche_config *generate_quiche_config() {
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
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);

    return config;

error:
    if (config) {
        quiche_config_free(config);
    }
    return NULL;
}

int main() {
    uv_loop_t *loop;
    uv_udp_t server_socket;
    server_context_t server_context = { 0 };

#ifdef DEBUG_LOG_FOR_QUICHE
    quiche_enable_debug_logging(quiche_debug_log, NULL);
#endif

    if (!(server_context.config = generate_quiche_config())) {
        LOG_ERROR("generate_quiche_config() failed");
        return -1;
    }

    loop = uv_default_loop();

    uv_udp_init(loop, &server_socket);
    server_socket.data = &server_context;

    struct sockaddr_in recv_addr;
    uv_ip4_addr("0.0.0.0", 8080, &recv_addr);

    uv_udp_bind(&server_socket, (const struct sockaddr *)&recv_addr, UV_UDP_REUSEADDR);
    uv_udp_recv_start(&server_socket, alloc_buffer, on_read);

    int r = uv_run(loop, UV_RUN_DEFAULT);

    quiche_config_free(server_context.config);

    return r;
}
