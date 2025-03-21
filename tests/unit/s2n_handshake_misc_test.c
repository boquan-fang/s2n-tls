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

#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_handshake.h"

#define MESSAGE_SIZE_LOCATION 1

S2N_RESULT s2n_rewrite_client_hello_length(struct s2n_stuffer *client_hello_stuffer, uint32_t length)
{
    /* Extend the stuffer to the desitred length */
    RESULT_GUARD_POSIX(s2n_stuffer_skip_write(client_hello_stuffer, length - client_hello_stuffer->blob.size));

    /* Rewrite the message length in header */
    uint32_t previous_write_cursor = client_hello_stuffer->write_cursor;
    client_hello_stuffer->write_cursor = MESSAGE_SIZE_LOCATION;
    RESULT_GUARD_POSIX(s2n_stuffer_write_uint24(client_hello_stuffer, length));
    client_hello_stuffer->write_cursor = previous_write_cursor;

    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    /* Test s2n_handshake_set_finished_len */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_SERVER), s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        const uint8_t max_len = sizeof(conn->handshake.client_finished);

        /* Safety */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(NULL, 0), S2N_ERR_NULL);

        /* Length must be less than available memory */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, UINT8_MAX), S2N_ERR_SAFETY);
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, max_len + 1), S2N_ERR_SAFETY);

        /* Length must be greater than zero */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, 0), S2N_ERR_SAFETY);

        /* Length can change from zero to a valid length */
        EXPECT_EQUAL(conn->handshake.finished_len, 0);
        EXPECT_OK(s2n_handshake_set_finished_len(conn, max_len));
        EXPECT_EQUAL(conn->handshake.finished_len, max_len);

        /* Length can't change if already set.
         * This method will be called when calculating both the client and server finished / verify_data.
         * Both client and server should have the same length, or something has gone wrong in our implementation.
         */
        EXPECT_ERROR_WITH_ERRNO(s2n_handshake_set_finished_len(conn, max_len - 1), S2N_ERR_SAFETY);
    };

    /* Test: client sends a large Client Hello */
    {
        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(client_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));

        DEFER_CLEANUP(struct s2n_config *server_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_NOT_NULL(server_config);
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(server_config));

        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "default_tls13"));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(server_config, "default_tls13"));

        EXPECT_SUCCESS(s2n_config_disable_x509_verification(client_config));

        DEFER_CLEANUP(struct s2n_connection *client = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(client);
        EXPECT_SUCCESS(s2n_connection_set_config(client, client_config));

        DEFER_CLEANUP(struct s2n_connection *server = s2n_connection_new(S2N_SERVER),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(server);
        EXPECT_SUCCESS(s2n_connection_set_config(server, server_config));

        /* Test: The client hello is slightly less than 64KB */
        {
            DEFER_CLEANUP(struct s2n_test_io_stuffer_pair io_pair = { 0 }, s2n_io_stuffer_pair_free);
            EXPECT_OK(s2n_io_stuffer_pair_init(&io_pair));
            EXPECT_OK(s2n_connections_set_io_stuffer_pair(client, server, &io_pair));

            // s2n_blocked_status blocked = S2N_NOT_BLOCKED;

            // s2n_negotiate(client, &blocked);
            // EXPECT_OK(s2n_rewrite_client_hello_length(&io_pair.client_in, ACCEPTABLE_CLIENT_HELLO_SIZE));
            EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(server, client, SERVER_HELLO));

        }

        /* Test: The client hello is larger than 64KB */
        {

        }
    }

    END_TEST();
}
