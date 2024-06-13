/*
  Copyright (c) 2024, MariaDB plc

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1335  USA */

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#define random_bytes(B,L) RAND_bytes(B,L)
#elif defined HAVE_GNUTLS
#include <nettle/eddsa.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha2.h>
#include <nettle/nettle-meta.h>
#include <nettle/hmac.h>
#include <gnutls/crypto.h>
#define random_bytes(B,L) gnutls_rnd(GNUTLS_RND_NONCE, B, L)
#elif defined HAVE_WINCRYPT
#endif


#include <errmsg.h>
#include <ma_global.h>
#include <mysql.h>
#include <mysql/client_plugin.h>
#include <string.h>

#define CHALLENGE_SCRAMBLE_LENGTH 32
#define CHALLENGE_SALT_LENGTH     30  /* Double the NIST recommendation */
#define ED25519_SIG_LENGTH        64
#define ED25519_KEY_LENGTH        32
#define PBKDF2_HASH_LENGTH        ED25519_KEY_LENGTH
#define CLIENT_RESPONSE_LENGTH    (CHALLENGE_SCRAMBLE_LENGTH + ED25519_SIG_LENGTH)

struct Server_challenge
{
  union
  {
    struct
    {
      uchar hash;
      uchar iterations;
      uchar salt[CHALLENGE_SALT_LENGTH];
    };
    uchar start[1];
  };
};

struct Client_signed_response
{
  union {
    struct {
      uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      uchar signature[ED25519_SIG_LENGTH];
    };
    uchar start[1];
  };
};

int compute_derived_key(const char* password, size_t pass_len,
                        const struct Server_challenge *params,
                        uchar *derived_key)
{
#if HAVE_OPENSSL
  return !PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                            CHALLENGE_SALT_LENGTH,
                            1 << (params->iterations + 10),
                            EVP_sha512(), PBKDF2_HASH_LENGTH, derived_key);
#else /* HAVE_GNUTLS */
  struct hmac_sha512_ctx ctx;
  hmac_sha512_set_key(&ctx, pass_len, (const uint8_t *)password);

  pbkdf2(&ctx, (nettle_hash_update_func *)hmac_sha512_update,
         (nettle_hash_digest_func *)hmac_sha512_digest, SHA512_DIGEST_SIZE,
         1024 << params->iterations, CHALLENGE_SALT_LENGTH, params->salt,
         PBKDF2_HASH_LENGTH, derived_key);

  return 0;
#endif
}

int ed25519_sign(const uchar* response, size_t response_len,
                 const uchar *private_key, uchar *signature)
{

#ifdef HAVE_OPENSSL
  int res= 1;
  size_t sig_len= ED25519_SIG_LENGTH;
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                private_key,
                                                ED25519_KEY_LENGTH);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx || !pkey)
    goto cleanup;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1 ||
      EVP_DigestSign(ctx, signature, &sig_len, response, response_len) != 1)
    goto cleanup;

  res= 0;
cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return res;
#else /* HAVE_GNUTLS */
  char pub[ED25519_KEY_LENGTH];
  ed25519_sha512_public_key((uint8_t*)pub, (uint8_t*)private_key);
  ed25519_sha512_sign((uint8_t*)pub, (uint8_t*)private_key,
                      response_len, (uint8_t*)response, (uint8_t*)signature);
  return 0;
#endif
}


static int auth(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  uchar *serv_scramble;
  union
  {
    struct
    {
      uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      struct Client_signed_response response;
    };
    uchar start[1];
  } signed_msg;
  struct Server_challenge *params;
  uchar priv_key[ED25519_KEY_LENGTH];
  int pkt_len;

  static_assert(sizeof(struct Server_challenge) == 2 + CHALLENGE_SALT_LENGTH);
  static_assert(sizeof(struct Client_signed_response) == CLIENT_RESPONSE_LENGTH);

  pkt_len= vio->read_packet(vio, (uchar**)(&serv_scramble));
  if (pkt_len != CHALLENGE_SCRAMBLE_LENGTH)
    return CR_SERVER_HANDSHAKE_ERR;

  memcpy(signed_msg.server_scramble, serv_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  if (vio->write_packet(vio, 0, 0) != 0) // empty packet = "need salt"
    return CR_ERROR;

  pkt_len= vio->read_packet(vio, (uchar**)&params);
  if (pkt_len != sizeof(struct Server_challenge))
    return CR_SERVER_HANDSHAKE_ERR;
  if (params->hash != 'P')
    return CR_AUTH_PLUGIN_ERR;
  if (params->iterations > 3)
    return CR_AUTH_PLUGIN_ERR;

  random_bytes(signed_msg.response.client_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  if (compute_derived_key(mysql->passwd, strlen(mysql->passwd),
                           params, priv_key))
    return CR_AUTH_PLUGIN_ERR;

  if (ed25519_sign(signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH*2,
                    priv_key, signed_msg.response.signature))
    return CR_AUTH_PLUGIN_ERR;

  if (vio->write_packet(vio, signed_msg.response.start,
                        sizeof signed_msg.response) != 0)
    return CR_ERROR;

  return CR_OK;
}


mysql_declare_client_plugin(AUTHENTICATION)
  "parsec",
  "Nikita Maliavin",
  "Password Authentication using Response Signed with Elliptic Curve",
  {0,1,0},
  "LGPL",
  NULL,
  NULL,
  NULL,
  NULL,
  auth,
  NULL,
mysql_end_client_plugin;
