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
#include "tls/s2n_tls13.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"

/* 10MB is far larger than any socket send buffer, which guarantees that the
 * sender will hit a write-blocked state at least once while transferring it. */
#define S2N_TEST_DATA_SIZE (10000000)

/* These numbers are chosen so that some of the payload is bigger than the max
 * TLS1.3 record size (2**14 + 1), which is needed to validate that we handle
 * record sizing correctly (see https://github.com/awslabs/s2n/pull/1780).
 *
 * Each iovec doubles the previous payload size to ensure the implementation
 * handles various lengths:
 * 8192, 16384, 32768, 65536, 131072, 262144, 524288 bytes. */
#define S2N_TEST_IOV_COUNT     (7)
#define S2N_TEST_IOV_BASE_SIZE (8192)

/* Transfers a contiguous payload from send_conn to recv_conn using s2n_send,
 * interleaving send and recv. Because the IO pair is non-blocking and both
 * peers run in the same process, a payload large enough to fill the socket
 * buffer would deadlock if we sent without draining, so we interleave.
 *
 * Verifies that the sender hits S2N_BLOCKED_ON_WRITE at least once (the core
 * behavior the original fork-based test coordinated with SIGSTOP/SIGCONT) and
 * that every byte is received correctly. */
static S2N_RESULT s2n_test_send_and_verify(struct s2n_connection *send_conn,
        struct s2n_connection *recv_conn, struct s2n_blob *blob)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    DEFER_CLEANUP(struct s2n_blob recv_blob = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&recv_blob, blob->size));

    uint32_t total_sent = 0;
    uint32_t total_received = 0;
    bool write_blocked = false;

    while (total_received < blob->size) {
        /* Send greedily until the socket buffer fills (S2N_BLOCKED_ON_WRITE)
         * or all data has been handed off. Draining after every send would
         * keep the buffer from ever filling, so we only drain once the sender
         * is blocked. */
        while (total_sent < blob->size) {
            ssize_t sent = s2n_send(send_conn, blob->data + total_sent,
                    blob->size - total_sent, &blocked);
            if (sent > 0) {
                total_sent += sent;
            } else {
                RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
                if (blocked == S2N_BLOCKED_ON_WRITE) {
                    write_blocked = true;
                }
                break;
            }
        }

        ssize_t received = s2n_recv(recv_conn, recv_blob.data + total_received,
                blob->size - total_received, &blocked);
        if (received > 0) {
            total_received += received;
        } else {
            RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }
    }

    RESULT_ENSURE(write_blocked, S2N_ERR_IO);
    RESULT_ENSURE_EQ(memcmp(blob->data, recv_blob.data, blob->size), 0);

    return S2N_RESULT_OK;
}

/* Transfers iovec-based payloads from send_conn to recv_conn. The bulk of the
 * data is sent via s2n_sendv_with_offset, and then the first iovec is sent once
 * more via s2n_sendv, mirroring the original test's coverage of both APIs.
 * Send and recv are interleaved to avoid deadlock, and the sender is expected
 * to hit S2N_BLOCKED_ON_WRITE at least once. */
static S2N_RESULT s2n_test_sendv_and_verify(struct s2n_connection *send_conn,
        struct s2n_connection *recv_conn, struct iovec *iov, uint32_t iov_count, uint32_t total_size)
{
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    uint32_t extra_size = iov[0].iov_len;
    uint32_t expected_size = total_size + extra_size;

    DEFER_CLEANUP(struct s2n_blob recv_blob = { 0 }, s2n_free);
    RESULT_GUARD_POSIX(s2n_alloc(&recv_blob, expected_size));

    uint32_t total_received = 0;
    bool write_blocked = false;

    /* Phase 1: send all the iovecs via s2n_sendv_with_offset. */
    uint32_t total_sent = 0;
    while (total_received < total_size) {
        /* Send greedily until blocked on write so the socket buffer fills. */
        while (total_sent < total_size) {
            ssize_t sent = s2n_sendv_with_offset(send_conn, iov, iov_count, total_sent, &blocked);
            if (sent > 0) {
                total_sent += sent;
            } else {
                RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
                if (blocked == S2N_BLOCKED_ON_WRITE) {
                    write_blocked = true;
                }
                break;
            }
        }

        ssize_t received = s2n_recv(recv_conn, recv_blob.data + total_received,
                expected_size - total_received, &blocked);
        if (received > 0) {
            total_received += received;
        } else {
            RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }
    }

    /* Phase 2: send the first iovec once more via s2n_sendv. We adjust a
     * single-element iovec to track the unsent remainder across partial sends. */
    struct iovec extra = { .iov_base = iov[0].iov_base, .iov_len = iov[0].iov_len };
    while (total_received < expected_size) {
        if (extra.iov_len > 0) {
            ssize_t sent = s2n_sendv(send_conn, &extra, 1, &blocked);
            if (sent > 0) {
                extra.iov_base = (uint8_t *) extra.iov_base + sent;
                extra.iov_len -= sent;
            } else {
                RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
            }
        }

        ssize_t received = s2n_recv(recv_conn, recv_blob.data + total_received,
                expected_size - total_received, &blocked);
        if (received > 0) {
            total_received += received;
        } else {
            RESULT_ENSURE_EQ(s2n_error_get_type(s2n_errno), S2N_ERR_T_BLOCKED);
        }
    }

    RESULT_ENSURE(write_blocked, S2N_ERR_IO);

    /* Verify the bulk data and the extra copy of the first iovec. */
    uint32_t offset = 0;
    for (uint32_t i = 0; i < iov_count; i++) {
        RESULT_ENSURE_EQ(memcmp(iov[i].iov_base, recv_blob.data + offset, iov[i].iov_len), 0);
        offset += iov[i].iov_len;
    }
    RESULT_ENSURE_EQ(memcmp(iov[0].iov_base, recv_blob.data + total_size, extra_size), 0);

    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_run_send_test(int use_tls13, int use_iov, int prefer_throughput,
        struct s2n_cert_chain_and_key *chain_and_key, char *dhparams_pem)
{
    /* Build the data to send. For the iovec case, point the iovecs into a
     * single contiguous blob so cleanup is simple. */
    DEFER_CLEANUP(struct s2n_blob blob = { 0 }, s2n_free);
    struct iovec iov[S2N_TEST_IOV_COUNT] = { 0 };
    uint32_t data_size = 0;

    if (!use_iov) {
        data_size = S2N_TEST_DATA_SIZE;
        RESULT_GUARD_POSIX(s2n_alloc(&blob, data_size));
        RESULT_GUARD(s2n_get_public_random_data(&blob));
    } else {
        uint32_t iov_payload_size = S2N_TEST_IOV_BASE_SIZE;
        for (size_t i = 0; i < S2N_TEST_IOV_COUNT; i++, iov_payload_size *= 2) {
            data_size += iov_payload_size;
        }
        RESULT_GUARD_POSIX(s2n_alloc(&blob, data_size));
        RESULT_GUARD(s2n_get_public_random_data(&blob));

        uint32_t offset = 0;
        iov_payload_size = S2N_TEST_IOV_BASE_SIZE;
        for (size_t i = 0; i < S2N_TEST_IOV_COUNT; i++, iov_payload_size *= 2) {
            iov[i].iov_base = blob.data + offset;
            iov[i].iov_len = iov_payload_size;
            offset += iov_payload_size;
        }
    }

    DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
    RESULT_ENSURE_REF(server_config);
    RESULT_GUARD_POSIX(s2n_config_add_cert_chain_and_key_to_store(server_config, chain_and_key));
    RESULT_GUARD_POSIX(s2n_config_add_dhparams(server_config, dhparams_pem));
    if (use_tls13) {
        RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(server_config, "test_all"));
    } else {
        RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(server_config, "test_all_tls12"));
    }

    DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
    RESULT_ENSURE_REF(client_config);
    RESULT_GUARD_POSIX(s2n_config_disable_x509_verification(client_config));
    RESULT_GUARD_POSIX(s2n_config_set_cipher_preferences(client_config, "test_all"));

    DEFER_CLEANUP(struct s2n_test_io_pair io_pair = { 0 }, s2n_io_pair_close);
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&io_pair));

    DEFER_CLEANUP(struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER),
            s2n_connection_ptr_free);
    RESULT_ENSURE_REF(server_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(server_conn, server_config));
    RESULT_GUARD_POSIX(s2n_connection_set_io_pair(server_conn, &io_pair));
    if (prefer_throughput) {
        RESULT_GUARD_POSIX(s2n_connection_prefer_throughput(server_conn));
    } else {
        RESULT_GUARD_POSIX(s2n_connection_prefer_low_latency(server_conn));
    }
    RESULT_GUARD_POSIX(s2n_connection_use_corked_io(server_conn));

    DEFER_CLEANUP(struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT),
            s2n_connection_ptr_free);
    RESULT_ENSURE_REF(client_conn);
    RESULT_GUARD_POSIX(s2n_connection_set_config(client_conn, client_config));
    RESULT_GUARD_POSIX(s2n_connection_set_io_pair(client_conn, &io_pair));

    /* Negotiate the handshake. */
    RESULT_GUARD_POSIX(s2n_negotiate_test_server_and_client(server_conn, client_conn));

    /* Make sure we negotiated the expected version. */
    if (use_tls13) {
        RESULT_ENSURE_EQ(server_conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());
    } else {
        RESULT_ENSURE_EQ(server_conn->actual_protocol_version, S2N_TLS12);
    }

    /* Transfer the data from the server to the client. */
    if (!use_iov) {
        RESULT_GUARD(s2n_test_send_and_verify(server_conn, client_conn, &blob));
    } else {
        RESULT_GUARD(s2n_test_sendv_and_verify(server_conn, client_conn, iov, S2N_TEST_IOV_COUNT, data_size));
    }

    RESULT_GUARD_POSIX(s2n_shutdown_test_server_and_client(server_conn, client_conn));

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *chain_and_key = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    char dhparams_pem[S2N_MAX_TEST_PEM_SIZE] = { 0 };
    EXPECT_SUCCESS(s2n_read_test_pem(S2N_DEFAULT_TEST_DHPARAMS, dhparams_pem, S2N_MAX_TEST_PEM_SIZE));

    for (int use_tls13 = 0; use_tls13 < 2; use_tls13++) {
        for (int use_iovec = 0; use_iovec < 2; use_iovec++) {
            for (int use_throughput = 0; use_throughput < 2; use_throughput++) {
                EXPECT_OK(s2n_run_send_test(use_tls13, use_iovec, use_throughput,
                        chain_and_key, dhparams_pem));
            }
        }
    }

    END_TEST();
}
