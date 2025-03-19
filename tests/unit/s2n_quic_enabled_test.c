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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "api/s2n.h"
#include "s2n_test.h"
#include "testlib/s2n_testlib.h"
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_tls13.h"

static const uint8_t fake_protocol[] = "fake-protocol";
static const uint8_t http3[] = "h3";
static const char server_name[255];

void mock_client(struct s2n_test_io_pair *io_pair)
{
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    s2n_blocked_status blocked;

    /* Give the server a chance to listen */
    sleep(1);

    conn = s2n_connection_new(S2N_CLIENT);
    config = s2n_config_new();
    s2n_config_disable_x509_verification(config);
    s2n_config_set_cipher_preferences(config, "default_tls13");

    EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, http3, sizeof(http3)));

    for (int i = 0; i < 4365; i ++) {
        EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, fake_protocol, sizeof(fake_protocol)));
    }

    EXPECT_NOT_NULL(memset((char *) server_name, 'a', 255));
    EXPECT_SUCCESS(s2n_set_server_name(conn, server_name));

    EXPECT_SUCCESS(s2n_config_enable_quic(config));

    s2n_connection_set_config(conn, config);

    s2n_connection_set_io_pair(conn, io_pair);
    s2n_connection_prefer_throughput(conn);

    s2n_negotiate(conn, &blocked);

    s2n_connection_free_handshake(conn);

    int shutdown_rc = -1;
    while (shutdown_rc != 0) {
        shutdown_rc = s2n_shutdown(conn, &blocked);
    }

    s2n_connection_free(conn);
    s2n_config_free(config);

    /* Give the server a chance to avoid a sigpipe */
    sleep(1);

    s2n_io_pair_close_one_end(io_pair, S2N_CLIENT);

    exit(0);
}

int main(int argc, char **argv)
{
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    s2n_blocked_status blocked;
    int status = 0;
    pid_t pid = 0;

    BEGIN_TEST();

    /* Create a pipe */
    struct s2n_test_io_pair io_pair;
    EXPECT_SUCCESS(s2n_io_pair_init(&io_pair));

    /* Create a child process */
    pid = fork();
    if (pid == 0) {
        /* This is the client process, close the server end of the pipe */
        EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

        /* Write the fragmented hello message */
        mock_client(&io_pair);
    }

    /* This is the server process, close the client end of the pipe */
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_CLIENT));

    EXPECT_NOT_NULL(conn = s2n_connection_new(S2N_SERVER));

    struct s2n_cert_chain_and_key *chain_and_key = NULL;
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&chain_and_key,
            S2N_DEFAULT_ECDSA_TEST_CERT_CHAIN, S2N_DEFAULT_ECDSA_TEST_PRIVATE_KEY));

    EXPECT_NOT_NULL(config = s2n_config_new());
    EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));
    EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, chain_and_key));

    EXPECT_SUCCESS(s2n_config_append_protocol_preference(config, http3, sizeof(http3)));

    EXPECT_SUCCESS(s2n_config_enable_quic(config));

    EXPECT_SUCCESS(s2n_connection_set_config(conn, config));
    EXPECT_SUCCESS(s2n_connection_prefer_throughput(conn));

    /* Set up the connection to read from the fd */
    EXPECT_SUCCESS(s2n_connection_set_io_pair(conn, &io_pair));

    /* Negotiate the handshake. */
    EXPECT_SUCCESS(s2n_negotiate(conn, &blocked));
    EXPECT_NOT_NULL(s2n_connection_get_client_hello(conn));
    EXPECT_EQUAL(conn->actual_protocol_version, s2n_get_highest_fully_supported_tls_version());

    int shutdown_rc = -1;
    do {
        shutdown_rc = s2n_shutdown(conn, &blocked);
        EXPECT_TRUE(shutdown_rc == 0 || (errno == EAGAIN && blocked));
    } while (shutdown_rc != 0);

    EXPECT_SUCCESS(s2n_connection_free(conn));
    EXPECT_SUCCESS(s2n_config_free(config));

    /* Clean up */
    EXPECT_EQUAL(waitpid(-1, &status, 0), pid);
    EXPECT_EQUAL(status, 0);
    EXPECT_SUCCESS(s2n_io_pair_close_one_end(&io_pair, S2N_SERVER));

    EXPECT_SUCCESS(s2n_cert_chain_and_key_free(chain_and_key));

    s2n_disable_tls13_in_test();

    END_TEST();
}
 