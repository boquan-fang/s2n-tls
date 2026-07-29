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
#include "tls/s2n_connection.h"
#include "tls/s2n_handshake.h"
#include "tls/s2n_security_policies.h"
#include "tls/s2n_tls.h"

/* The transcript hashes that s2n_conn_update_handshake_hashes can actually update.
 * S2N_HASH_NONE and S2N_HASH_SHAKE256_64 have no transcript state, and the
 * combined MD5_SHA1 state is derived from MD5 and SHA1 rather than from its own
 * entry in required_hash_algs. */
static const s2n_hash_algorithm transcript_hashes[] = {
    S2N_HASH_MD5,
    S2N_HASH_SHA1,
    S2N_HASH_SHA224,
    S2N_HASH_SHA256,
    S2N_HASH_SHA384,
    S2N_HASH_SHA512,
};

static S2N_RESULT s2n_count_required_hashes(struct s2n_connection *conn, size_t *count)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(count);
    *count = 0;
    for (size_t i = 0; i < s2n_array_len(transcript_hashes); i++) {
        if (s2n_handshake_is_hash_required(&conn->handshake, transcript_hashes[i])) {
            (*count)++;
        }
    }
    return S2N_RESULT_OK;
}

/* required_hash_algs must never contain a hash the security policy ruled out.
 * If it did, that hash state would be missing earlier transcript messages while
 * still being advertised as usable. */
static S2N_RESULT s2n_assert_subset_of_policy(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);

    const struct s2n_security_policy *policy = NULL;
    RESULT_GUARD_POSIX(s2n_connection_get_security_policy(conn, &policy));

    uint8_t possible[S2N_HASH_ALGS_COUNT] = { 0 };
    RESULT_GUARD(s2n_security_policy_get_required_hash_algs(policy, possible));

    for (size_t i = 0; i < s2n_array_len(transcript_hashes); i++) {
        s2n_hash_algorithm hash_alg = transcript_hashes[i];
        if (s2n_handshake_is_hash_required(&conn->handshake, hash_alg)) {
            RESULT_ENSURE_EQ(possible[hash_alg], 1);
        }
    }
    return S2N_RESULT_OK;
}

static S2N_RESULT s2n_assert_prf_hash_required(struct s2n_connection *conn)
{
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE_REF(conn->secure);
    RESULT_ENSURE_REF(conn->secure->cipher_suite);

    if (conn->actual_protocol_version < S2N_TLS12) {
        /* The legacy PRF uses both MD5 and SHA1 */
        RESULT_ENSURE_EQ(s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_MD5), 1);
        RESULT_ENSURE_EQ(s2n_handshake_is_hash_required(&conn->handshake, S2N_HASH_SHA1), 1);
        return S2N_RESULT_OK;
    }

    s2n_hash_algorithm prf_hash = S2N_HASH_NONE;
    RESULT_GUARD_POSIX(s2n_hmac_hash_alg(conn->secure->cipher_suite->prf_alg, &prf_hash));
    RESULT_ENSURE_EQ(s2n_handshake_is_hash_required(&conn->handshake, prf_hash), 1);
    return S2N_RESULT_OK;
}

static int s2n_test_swap_config_client_hello_cb(struct s2n_connection *conn, void *ctx)
{
    POSIX_GUARD(s2n_connection_set_config(conn, (struct s2n_config *) ctx));
    return S2N_SUCCESS;
}

struct s2n_test_conn_pair {
    struct s2n_connection *client;
    struct s2n_connection *server;
    struct s2n_test_io_pair io_pair;
};

static S2N_RESULT s2n_test_conn_pair_init(struct s2n_test_conn_pair *pair,
        struct s2n_config *client_config, struct s2n_config *server_config)
{
    RESULT_ENSURE_REF(pair);
    pair->client = s2n_connection_new(S2N_CLIENT);
    RESULT_ENSURE_REF(pair->client);
    pair->server = s2n_connection_new(S2N_SERVER);
    RESULT_ENSURE_REF(pair->server);
    RESULT_GUARD_POSIX(s2n_connection_set_config(pair->client, client_config));
    RESULT_GUARD_POSIX(s2n_connection_set_config(pair->server, server_config));
    RESULT_GUARD_POSIX(s2n_io_pair_init_non_blocking(&pair->io_pair));
    RESULT_GUARD_POSIX(s2n_connections_set_io_pair(pair->client, pair->server, &pair->io_pair));
    return S2N_RESULT_OK;
}

static S2N_CLEANUP_RESULT s2n_test_conn_pair_free(struct s2n_test_conn_pair *pair)
{
    RESULT_ENSURE_REF(pair);
    RESULT_GUARD_POSIX(s2n_connection_free(pair->client));
    RESULT_GUARD_POSIX(s2n_connection_free(pair->server));
    RESULT_GUARD_POSIX(s2n_io_pair_close(&pair->io_pair));
    return S2N_RESULT_OK;
}

int main(int argc, char **argv)
{
    BEGIN_TEST();

    DEFER_CLEANUP(struct s2n_cert_chain_and_key *rsa_chain = NULL, s2n_cert_chain_and_key_ptr_free);
    EXPECT_SUCCESS(s2n_test_cert_chain_and_key_new(&rsa_chain,
            S2N_DEFAULT_TEST_CERT_CHAIN, S2N_DEFAULT_TEST_PRIVATE_KEY));

    /* A new connection requires every transcript hash, because no security policy
     * has been applied yet. */
    {
        DEFER_CLEANUP(struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT),
                s2n_connection_ptr_free);
        EXPECT_NOT_NULL(conn);
        EXPECT_SUCCESS(s2n_connection_set_cipher_preferences(conn, "null"));

        size_t count = 0;
        EXPECT_OK(s2n_count_required_hashes(conn, &count));
        EXPECT_EQUAL(count, s2n_array_len(transcript_hashes));
    };

    /* The client narrows to the policy's possible hashes when it writes its
     * ClientHello, and to the negotiated PRF hash once it reads the ServerHello.
     *
     * The server never hedges at all: it negotiates the cipher suite while
     * handling the ClientHello, before that message is added to the transcript,
     * so it is already down to the PRF hash before it hashes anything. Narrowing
     * by policy must not undo that. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_chain));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "default_tls13"));

        DEFER_CLEANUP(struct s2n_test_conn_pair pair = { 0 }, s2n_test_conn_pair_free);
        EXPECT_OK(s2n_test_conn_pair_init(&pair, config, config));

        /* Before the ClientHello is sent, both peers still require everything */
        size_t count = 0;
        EXPECT_OK(s2n_count_required_hashes(pair.client, &count));
        EXPECT_EQUAL(count, s2n_array_len(transcript_hashes));
        EXPECT_OK(s2n_count_required_hashes(pair.server, &count));
        EXPECT_EQUAL(count, s2n_array_len(transcript_hashes));

        /* After the ClientHello, the client is down to the policy's hashes.
         * default_tls13 still permits TLS1.2, so its TLS1.2 signature preferences
         * contribute SHA512 on top of the two possible PRF hashes. The legacy
         * hashes are ruled out. */
        EXPECT_OK(s2n_negotiate_test_server_and_client_until_message(pair.server, pair.client,
                SERVER_HELLO));
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_MD5), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_SHA1), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_SHA224), 0);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_SHA256), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_SHA384), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_SHA512), 1);

        /* The server has already reached the single negotiated hash */
        EXPECT_OK(s2n_count_required_hashes(pair.server, &count));
        EXPECT_EQUAL(count, 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.server->handshake, S2N_HASH_SHA256), 1);

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(pair.server, pair.client));
        EXPECT_EQUAL(pair.server->actual_protocol_version, S2N_TLS13);

        /* Both peers end on exactly the negotiated hash */
        EXPECT_OK(s2n_count_required_hashes(pair.client, &count));
        EXPECT_EQUAL(count, 1);
        EXPECT_OK(s2n_count_required_hashes(pair.server, &count));
        EXPECT_EQUAL(count, 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.client->handshake, S2N_HASH_SHA256), 1);
        EXPECT_EQUAL(s2n_handshake_is_hash_required(&pair.server->handshake, S2N_HASH_SHA256), 1);
    };

    /* Narrowing must never widen an already narrowed set, for any policy, in
     * either mode, with or without client auth.
     *
     * Client auth is the interesting case: in TLS1.2 the CertificateVerify
     * transcript hash is chosen from the policy's signature preferences, so
     * s2n_conn_update_required_handshake_hashes re-enables every hash until that
     * message is past. Those hashes must still be restricted to the policy,
     * otherwise a hash gets marked usable while missing earlier messages. */
    {
        const s2n_cert_auth_type auth_types[] = { S2N_CERT_AUTH_NONE, S2N_CERT_AUTH_REQUIRED };
        const char *policies[] = {
            "default",
            "default_tls13",
            "default_fips",
            "20170210",
            "20190801",
            "20240501",
            "20250414",
            "test_all_tls12",
        };

        for (size_t p = 0; p < s2n_array_len(policies); p++) {
            for (size_t a = 0; a < s2n_array_len(auth_types); a++) {
                DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
                EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_chain));
                EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
                EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, policies[p]));
                EXPECT_SUCCESS(s2n_config_set_client_auth_type(config, auth_types[a]));

                DEFER_CLEANUP(struct s2n_test_conn_pair pair = { 0 }, s2n_test_conn_pair_free);
                EXPECT_OK(s2n_test_conn_pair_init(&pair, config, config));

                EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(pair.server, pair.client));

                EXPECT_OK(s2n_assert_subset_of_policy(pair.client));
                EXPECT_OK(s2n_assert_subset_of_policy(pair.server));
                EXPECT_OK(s2n_assert_prf_hash_required(pair.client));
                EXPECT_OK(s2n_assert_prf_hash_required(pair.server));

                /* Once the handshake is complete, only the PRF hash is needed */
                size_t count = 0;
                EXPECT_OK(s2n_count_required_hashes(pair.server, &count));
                EXPECT_TRUE(count <= 2);
                EXPECT_OK(s2n_count_required_hashes(pair.client, &count));
                EXPECT_TRUE(count <= 2);
            }
        }
    };

    /* Replacing the config during the client hello callback must still leave the
     * server able to complete the handshake: narrowing is recomputed from the
     * policy that is actually in effect. */
    {
        DEFER_CLEANUP(struct s2n_config *initial_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(initial_config, rsa_chain));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(initial_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(initial_config, "20250414"));

        DEFER_CLEANUP(struct s2n_config *swapped_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(swapped_config, rsa_chain));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(swapped_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(swapped_config, "20170210"));

        DEFER_CLEANUP(struct s2n_config *client_config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(client_config, rsa_chain));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(client_config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(client_config, "test_all_tls12"));

        EXPECT_SUCCESS(s2n_config_set_client_hello_cb(initial_config,
                s2n_test_swap_config_client_hello_cb, swapped_config));

        DEFER_CLEANUP(struct s2n_test_conn_pair pair = { 0 }, s2n_test_conn_pair_free);
        EXPECT_OK(s2n_test_conn_pair_init(&pair, client_config, initial_config));

        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(pair.server, pair.client));
        EXPECT_EQUAL(pair.server->config, swapped_config);
        EXPECT_OK(s2n_assert_subset_of_policy(pair.server));
        EXPECT_OK(s2n_assert_prf_hash_required(pair.server));
    };

    /* Renegotiation wipes the connection, so the next handshake must start from
     * the full set again rather than from the previous handshake's narrowed set. */
    {
        DEFER_CLEANUP(struct s2n_config *config = s2n_config_new(), s2n_config_ptr_free);
        EXPECT_SUCCESS(s2n_config_add_cert_chain_and_key_to_store(config, rsa_chain));
        EXPECT_SUCCESS(s2n_config_set_unsafe_for_testing(config));
        EXPECT_SUCCESS(s2n_config_set_cipher_preferences(config, "20170210"));

        DEFER_CLEANUP(struct s2n_test_conn_pair pair = { 0 }, s2n_test_conn_pair_free);
        EXPECT_OK(s2n_test_conn_pair_init(&pair, config, config));
        EXPECT_SUCCESS(s2n_negotiate_test_server_and_client(pair.server, pair.client));

        size_t count = 0;
        EXPECT_OK(s2n_count_required_hashes(pair.server, &count));
        EXPECT_TRUE(count <= 2);

        EXPECT_SUCCESS(s2n_connection_wipe(pair.server));
        EXPECT_OK(s2n_count_required_hashes(pair.server, &count));
        EXPECT_EQUAL(count, s2n_array_len(transcript_hashes));
    };

    END_TEST();
}
