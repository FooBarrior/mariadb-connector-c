/*
   Copyright (c) 2023, MariaDB Corporation.

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

#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "errmsg.h"
#include "ma_global.h"
#include <mysql.h>
#include <mysql/client_plugin.h>

#include "ed25519v2_common.h"

bool compute_derived_key(const char* password, size_t pass_len,
                         const Server_challenge *params, uchar *derived_key)
{
  int ret = PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                              CHALLENGE_SALT_LENGTH,
                              1 << (params->iterations + 10),
                              EVP_sha512(),
                              PBKDF2_HASH_LENGTH, derived_key);
  if(ret == 0)
     ERR_print_errors_fp(stderr);
  return ret;
}


bool ed25519_sign(const uchar* response, size_t response_len,
                  const uchar *private_key,
                  uchar *signature)
{
  bool res= false;
  size_t sig_len= ED25519_SIG_LENGTH;
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                private_key,
                                                ED25519_KEY_LENGTH);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx || !pkey)
    goto cleanup;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1 ||
      EVP_DigestSign(ctx, signature, &sig_len, response, response_len) != 1)
  {
    ERR_print_errors_fp(stderr);
    goto cleanup;
  }

  res= true;
cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return res;
}


static int auth(MYSQL_PLUGIN_VIO *vio, MYSQL *mysql)
{
  uchar *serv_scramble;
  int pkt_len= vio->read_packet(vio, (uchar**)(&serv_scramble));
  if (pkt_len != CHALLENGE_SCRAMBLE_LENGTH)
    return CR_SERVER_HANDSHAKE_ERR;

  union
  {
    struct alignas (1)
    {
      uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      Client_signed_response response;
    };
    uchar start[1];
  } signed_msg;
  memcpy(signed_msg.server_scramble, serv_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  Server_challenge *params;
  pkt_len= vio->read_packet(vio, reinterpret_cast<uchar**>(&params));
  if (pkt_len != sizeof(Server_challenge))
    return CR_SERVER_HANDSHAKE_ERR;
  if (params->hash != 'P')
    return CR_WRONG_HOST_INFO;

  char scramble[]= "12345678901234567890123456789012";
  memcpy(signed_msg.response.client_scramble, scramble,
         CHALLENGE_SCRAMBLE_LENGTH);

  uchar priv_key[ED25519_KEY_LENGTH];
  if (!compute_derived_key(mysql->passwd, strlen(mysql->passwd),
                           params, priv_key))
    return CR_ERROR;

  if (!ed25519_sign(signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH*2,
                    priv_key, signed_msg.response.signature))
    return CR_ERROR;

  if (vio->write_packet(vio, signed_msg.response.start,
                        sizeof signed_msg.response) != 0)
    return CR_ERROR;

  return CR_OK;
}


static int init_client(char *unused1   __attribute__((unused)),
                       size_t unused2  __attribute__((unused)),
                       int unused3     __attribute__((unused)),
                       va_list unused4 __attribute__((unused)))
{
  return 0;
}

mysql_declare_client_plugin(AUTHENTICATION)
  "client_ed25519v2",
  "Nikita Maliavin",
  "ED25519 v2 - asymmetric challenge-based authentication (client)",
  {0,2,0},
  "GPL",
  NULL,
  init_client,
  NULL,
  NULL,
  auth,
  NULL,
mysql_end_client_plugin;

