/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <stdint.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"

struct client_hello_context {
    int invoked;
    int swap_config_during_callback;
    int swap_config_nonblocking_mode;
    int mark_done_during_callback;
    struct s2n_config *config;
    /* the right way to mark server name extenstion was used
     * after parsing ClientHello is to call
     * s2n_connection_server_name_extension_used
     *
     * this flag tests the previous behavior from blocking callbacks
     */
    int legacy_rc_for_server_name_used;
};

int client_hello_swap_config(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx = NULL;
    struct s2n_client_hello *client_hello = s2n_connection_get_client_hello(conn);
    const char *sent_server_name = "example.com";
    const char *received_server_name = NULL;
    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;
    /* Increment counter to ensure that callback was invoked */
    client_hello_ctx->invoked++;

    /* Validate SNI extension */
    uint8_t expected_server_name[] = {
        /* Server names len */
        0x00, 0x0E,
        /* Server name type - host name */
        0x00,
        /* First server name len */
        0x00, 0x0B,
        /* First server name, matches sent_server_name */
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
    };

    /* Get SNI extension from client hello */
    uint32_t len = s2n_client_hello_get_extension_length(client_hello, S2N_EXTENSION_SERVER_NAME);
    if (len != 16) {
        return -1;
    }

    uint8_t ser_name[16] = { 0 };
    if (s2n_client_hello_get_extension_by_id(client_hello, S2N_EXTENSION_SERVER_NAME, ser_name, len) <= 0) {
        return -1;
    }

    /* Verify correct server name is returned. */
    received_server_name = s2n_get_server_name(conn);
    if (received_server_name == NULL || strcmp(received_server_name, sent_server_name)) {
        return -1;
    }

    if (memcmp(ser_name, expected_server_name, len) != 0) {
        return -1;
    }

    if (client_hello_ctx->mark_done_during_callback) {
        EXPECT_SUCCESS(s2n_client_hello_cb_done(conn));
    }

    if (client_hello_ctx->swap_config_during_callback) {
        EXPECT_SUCCESS(s2n_connection_set_config(conn, client_hello_ctx->config));
        if (client_hello_ctx->legacy_rc_for_server_name_used) {
            return 1;
        }
        EXPECT_SUCCESS(s2n_connection_server_name_extension_used(conn));
        return 0;
    }

    return 0;
}

int client_hello_fail_handshake(struct s2n_connection *conn, void *ctx)
{
    struct client_hello_context *client_hello_ctx = NULL;

    if (ctx == NULL) {
        return -1;
    }
    client_hello_ctx = ctx;

    /* Incremet counter to ensure that callback was invoked */
    client_hello_ctx->invoked++;

    /* Return negative value to terminate the handshake */
    return -1;
}

/* Configures a client connection the same way the original forked mock client
 * did: TLS1.2, ALPN preferences, no certificate validation, and an SNI. */
static S2N_RESULT s2n_setup_client(struct s2n_connection *client_conn, struct s2n_config *client_config)
{
    static const char *protocols[] = { "h2", "http/1.1" };
    RESULT_ENSURE_REF(client_conn);
    RESULT_ENSURE_REF(client_config);

    RESULT_GUARD(s2n_connection_set_tls12_security_policy(client_conn));
    RESULT_GUARD_POSIX(s2n_config_set_protocol_preferences(client_config, protocols, 2));
    RESULT_GUARD_POSIX(s2n_config_disable_x509_verification(client_config));
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, client_config));
    RESULT_GUARD_POSIX(s2n_set_server_name(client_conn, "example.com"));

    return S2N_RESULT_OK;
}

/* Drives a handshake to completion when the server uses a non-blocking
 * client_hello callback. The handshake pauses with S2N_ERR_ASYNC_BLOCKED once
 * the callback has been invoked. This mirrors the original test's behavior:
 * optionally swap the config while paused, verify the handshake stays paused
 * until explicitly unblocked, then mark the callback done and finish. */
static S2N_RESULT s2n_negotiate_nonblocking_ch_cb(struct s2n_connection *server_conn,
        struct s2n_connection *client_conn, struct client_hello_context *ch_ctx, bool server_name_used)
{
    /* Negotiate until the handshake pauses after the callback is invoked. */
    RESULT_ENSURE_EQ(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_FAILURE);
    RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_ASYNC_BLOCKED);
    RESULT_ENSURE_EQ(ch_ctx->invoked, 1);

    /* While the handshake is paused, swap the config if asked. */
    if (ch_ctx->swap_config_nonblocking_mode) {
        RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, ch_ctx->config));
    }

    /* Unless explicitly unblocked, the handshake stays paused. */
    RESULT_ENSURE_EQ(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_FAILURE);
    RESULT_ENSURE_EQ(s2n_errno, S2N_ERR_ASYNC_BLOCKED);

    /* Mark the client hello callback complete. */
    RESULT_GUARD_POSIX(s2n_client_hello_cb_done(server_conn));
    if (server_name_used) {
        RESULT_GUARD_POSIX(s2n_connection_server_name_extension_used(server_conn));
    }

    /* Finish the handshake. */
    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    return S2N_RESULT_OK;
}

/* Sends a range of payload sizes from the client to the server and verifies
 * every byte is received correctly. Because the IO pair is non-blocking and
 * both peers run in the same process, interleave send and recv so a large
 * payload that fills the in-memory buffer can't deadlock. */
static S2N_RESULT s2n_send_and_recv_range(struct s2n_connection *send_conn, struct s2n_connection *recv_conn)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    uint8_t send_buffer[0xffff] = { 0 };
    uint8_t recv_buffer[0xffff] = { 0 };

    for (size_t size = 1; size < s2n_array_len(send_buffer); size += 100) {
        RESULT_CHECKED_MEMSET(&send_buffer[0], 33, size);

        size_t total_sent = 0;
        size_t total_received = 0;
        while (total_received < size) {
            if (total_sent < size) {
                ssize_t sent = s2n_send(send_conn, send_buffer + total_sent,
                        size - total_sent, &blocked);
                if (sent > 0) {
                    total_sent += sent;
                } else {
                    RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
                }
            }

            ssize_t received = s2n_recv(recv_conn, recv_buffer + total_received,
                    size - total_received, &blocked);
            if (received > 0) {
                total_received += received;
            } else {
                RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }
        }

        RESULT_ENSURE_EQ(total_received, size);
        for (size_t j = 0; j < size; j++) {
            RESULT_ENSURE_EQ(recv_buffer[j], 33);
        }
    }

    return S2N_RESULT_OK;
}

int run_test_config_swap_ch_cb(s2n_client_hello_cb_mode cb_mode,
        struct client_hello_context *ch_ctx)
{
    /* Add application protocols to swapped config */
    static const char *protocols[] = { "h2" };

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* prepare swap_config */
    DEFER_CLEANUP(struct s2n_config *swap_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(swap_config);
    EXPECT_OK(s2n_config_set_tls12_security_policy(swap_config));
    EXPECT_SUCCESS(s2n_config_set_protocol_preferences(swap_config, protocols, 1));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(swap_config, chain_and_key));
    ch_ctx->config = swap_config;
    /* in the swap config make sure blocking more is SET correctly */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(swap_config, cb_mode));

    /* Don't set up certificate and private key for the main config, so if
     * handshake succeeds we know that config was swapped */
    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);

    /* Set up the callback */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, cb_mode));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, ch_ctx));

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(server_conn);
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(client_config);
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(client_conn);
    EXPECT_OK(s2n_setup_client(client_conn, client_config));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

    /* do the handshake */
    if (cb_mode == S2N_CLIENT_HELLO_CB_NONBLOCKING && !ch_ctx->mark_done_during_callback) {
        /* swap the config and mark server_name_used in the async context */
        EXPECT_OK(s2n_negotiate_nonblocking_ch_cb(server_conn, client_conn, ch_ctx, true));
    } else {
        /* cb_mode == S2N_CLIENT_HELLO_CB_BLOCKING or NONBLOCKING mode where
         * a non blocking callback marks cb_done during the callback itself
         */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(ch_ctx->invoked, 1);
    }

    /* Server name and error are as expected with null connection */
    EXPECT_NULL(s2n_get_server_name(NULL));
    EXPECT_EQUAL(s2n_errno, S2N_ERR_NULL);

    /* The client should observe that the server used the server name extension */
    EXPECT_EQUAL(client_conn->server_name_used, 1);

    /* Expect most preferred negotiated protocol which only swap_config had */
    EXPECT_STRING_EQUAL(s2n_get_application_protocol(server_conn), protocols[0]);

    /* Transfer application data from client to server */
    EXPECT_OK(s2n_send_and_recv_range(client_conn, server_conn));

    EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    memset(ch_ctx, 0, sizeof(struct client_hello_context));
    return S2N_SUCCESS;
}

int run_test_no_config_swap_ch_cb(s2n_client_hello_cb_mode cb_mode, struct client_hello_context *ch_ctx)
{
    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_OK(s2n_config_set_tls12_security_policy(config));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Setup ClientHello callback */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_swap_config, ch_ctx));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, cb_mode));

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(server_conn);
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(client_config);
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(client_conn);
    EXPECT_OK(s2n_setup_client(client_conn, client_config));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

    /* do the handshake */
    if (cb_mode == S2N_CLIENT_HELLO_CB_NONBLOCKING) {
        /* the callback does not mark server_name_used */
        EXPECT_OK(s2n_negotiate_nonblocking_ch_cb(server_conn, client_conn, ch_ctx, false));
    } else { /* cb_mode == S2N_CLIENT_HELLO_CB_BLOCKING */
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(server_conn, client_conn));
        EXPECT_EQUAL(ch_ctx->invoked, 1);
    }

    /* Server name and error are as expected with null connection */
    EXPECT_NULL(s2n_get_server_name(NULL));
    EXPECT_EQUAL(s2n_errno, S2N_ERR_NULL);

    /* The server name extension was not marked used in this scenario */
    EXPECT_EQUAL(client_conn->server_name_used, 0);

    /* Transfer application data from client to server */
    EXPECT_OK(s2n_send_and_recv_range(client_conn, server_conn));

    EXPECT_SUCCESS(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    memset(ch_ctx, 0, sizeof(struct client_hello_context));
    return S2N_SUCCESS;
}

int run_test_reject_handshake_ch_cb(s2n_client_hello_cb_mode cb_mode, struct client_hello_context *ch_ctx)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key, S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(config);
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    /* Setup ClientHello callback */
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb(config, client_hello_fail_handshake, ch_ctx));
    EXPECT_SUCCESS(s2n_config_set_client_hello_cb_mode(config, cb_mode));

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    EXPECT_SUCCESS(s2n_io_pair_init_non_blocking(&io_pair));

    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(server_conn);
    EXPECT_SUCCESS(s2n_connection_set_config(server_conn, config));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(server_conn, &io_pair));
    /* If s2n_negotiate fails, it usually would delay with a sleep. In order to
     * test that we don't blind when ClientHello callback fails the handshake,
     * disable blinding here */
    EXPECT_SUCCESS(s2n_connection_set_blinding(server_conn, S2N_SELF_SERVICE_BLINDING));

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
    EXPECT_NOT_NULL(client_config);
    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT), s2n_connection_ptr_free);
    EXPECT_NOT_NULL(client_conn);
    EXPECT_OK(s2n_setup_client(client_conn, client_config));
    EXPECT_SUCCESS(s2n_connection_set_io_pair(client_conn, &io_pair));

    /* Negotiate the handshake. The server rejects the connection in the
     * ClientHello callback, so negotiation fails with S2N_ERR_CANCELLED. */
    EXPECT_FAILURE_WITH_ERRNO(s2n_negotiate_test_server_and_client(server_conn, client_conn), S2N_ERR_CANCELLED);

    /* Check that blinding was not invoked */
    EXPECT_EQUAL(s2n_connection_get_delay(server_conn), 0);

    /* Ensure that callback was invoked */
    EXPECT_EQUAL(ch_ctx->invoked, 1);

    /* The server queues a fatal alert. Flush it to the client and verify the
     * client receives a handshake_failure (40) alert. */
    EXPECT_SUCCESS(s2n_shutdown(server_conn, &blocked));
    for (size_t i = 0; i < 10; i++) {
        int client_rc = s2n_negotiate(client_conn, &blocked);
        EXPECT_TRUE(client_rc < 0);
        if (s2n_error_get_type(s2n_errno) != S2N_ERR_T_BLOCKED) {
            /* The client read the fatal alert and stopped the handshake. */
            break;
        }
    }
    EXPECT_EQUAL(s2n_connection_get_alert(client_conn), 40);

    memset(ch_ctx, 0, sizeof(struct client_hello_context));
    return S2N_SUCCESS;
}

int main(int argc, char **argv)
{
    struct client_hello_context client_hello_ctx = { 0 };
    BEGIN_TEST();
    /* Test config swapping in client hello callback */

    /* we want to update the config outside of callback so don't swap in callback */
    client_hello_ctx.swap_config_nonblocking_mode = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    /* non blocking callback when callback marks cb_done during the callback */
    client_hello_ctx.swap_config_during_callback = 1;
    client_hello_ctx.mark_done_during_callback = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    /* we want to update the config in the callback */
    client_hello_ctx.swap_config_during_callback = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    /* validate legacy behavior for server_name_used */
    /* we want to update the config in the callback */
    client_hello_ctx.swap_config_during_callback = 1;
    client_hello_ctx.legacy_rc_for_server_name_used = 1;
    EXPECT_SUCCESS(run_test_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    /* Tests for test when server_name_used is not set */
    EXPECT_SUCCESS(run_test_no_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    EXPECT_SUCCESS(run_test_no_config_swap_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    /* Test rejecting connection in client hello callback */
    EXPECT_SUCCESS(run_test_reject_handshake_ch_cb(S2N_CLIENT_HELLO_CB_BLOCKING, &client_hello_ctx));

    EXPECT_SUCCESS(run_test_reject_handshake_ch_cb(S2N_CLIENT_HELLO_CB_NONBLOCKING, &client_hello_ctx));

    END_TEST();

    return 0;
}
