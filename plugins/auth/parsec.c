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
#elif defined HAVE_SCHANNEL
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
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

struct Passwd_in_memory
{
  char algorithm;
  uchar iterations;
  uchar salt[CHALLENGE_SALT_LENGTH];
  uchar pub_key[ED25519_KEY_LENGTH];
};

static_assert(sizeof(struct Passwd_in_memory) == 2 + CHALLENGE_SALT_LENGTH + ED25519_KEY_LENGTH);

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

static_assert(sizeof(struct Client_signed_response) == CLIENT_RESPONSE_LENGTH);

int compute_derived_key(const char* password, size_t pass_len,
                        const struct Passwd_in_memory *params,
                        uchar *derived_key)
{
#if HAVE_OPENSSL
  return !PKCS5_PBKDF2_HMAC(password, (int)pass_len, params->salt,
                            CHALLENGE_SALT_LENGTH,
                            1 << (params->iterations + 10),
                            EVP_sha512(), PBKDF2_HASH_LENGTH, derived_key);

#elif defined HAVE_SCHANNEL
  NTSTATUS status;
  BCRYPT_ALG_HANDLE hAlgorithm = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  ULONG derived_key_len = PBKDF2_HASH_LENGTH;
  int ret = 1;

  const char *func= "BCryptOpenAlgorithmProvider";
  status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!BCRYPT_SUCCESS(status))
    goto err;

  func= "BCryptOpenAlgorithmProvider";
  status = BCryptDeriveKeyPBKDF2(hAlgorithm,
                                (PUCHAR)password, (ULONG)pass_len,
                                (PUCHAR)params->salt, CHALLENGE_SALT_LENGTH,
                                1ULL << (params->iterations + 10),
                                derived_key, derived_key_len,
                                0);
  if (!BCRYPT_SUCCESS(status))
    goto err;

  ret = 0;
cleanup:
  if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);

  return ret;
err:
  fprintf(stderr, "%s failed: 0x%08x\n", func, status);
  goto cleanup;
#elif 0

  BCRYPT_ALG_HANDLE hAlg = NULL;
  NTSTATUS status;
  DWORD derived_key_len = PBKDF2_HASH_LENGTH;

  status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_PBKDF2_ALGORITHM, NULL, 0);
  if (status != 0) {
    fprintf(stderr, "BCryptOpenAlgorithmProvider error: 0x%x\n", status);
    return 1;
  }

  status = BCryptDeriveKeyPBKDF2(hAlg,
                                (PUCHAR)password, (ULONG)pass_len,
                                (PUCHAR)params->salt, CHALLENGE_SALT_LENGTH,
                                (ULONG)(1 << (params->iterations + 10)),
                                derived_key, derived_key_len, 0);
  if (status != 0) {
    fprintf(stderr, "BCryptDeriveKeyPBKDF2 error: 0x%x\n", status);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
  }

  BCryptCloseAlgorithmProvider(hAlg, 0);
  return 0;
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

int ed25519_sign(const uchar *response, size_t response_len,
                 const uchar *private_key, uchar *signature,
                 uchar *public_key)
{
#ifdef HAVE_OPENSSL
  int res= 1;
  size_t sig_len= ED25519_SIG_LENGTH, pklen= ED25519_KEY_LENGTH;
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                private_key,
                                                ED25519_KEY_LENGTH);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx || !pkey)
    goto cleanup;

  if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) != 1 ||
      EVP_DigestSign(ctx, signature, &sig_len, response, response_len) != 1)
    goto cleanup;

  EVP_PKEY_get_raw_public_key(pkey, public_key, &pklen);

  res= 0;
cleanup:
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return res;
#elif defined HAVE_SCHANNEL
  void *key= NULL;
  NCRYPT_PROV_HANDLE hProvider = 0;
  NCRYPT_KEY_HANDLE hKey = 0;
  BCRYPT_KEY_HANDLE hbKey = 0;
  SECURITY_STATUS status;
  DWORD keyBlobLen = 0;
  DWORD sigLen = ED25519_SIG_LENGTH;
  int result = 1;

  BCRYPT_ALG_HANDLE pAlg;
  const char curve_name[]= "curve25519";
  const char *func = "BCryptOpenAlgorithmProvider";
  status = BCryptOpenAlgorithmProvider(&pAlg, BCRYPT_ECDH_ALGORITHM, NULL, 0);
  if (status != ERROR_SUCCESS)
    goto err;

  func = "BCryptSetProperty(alg)";
  status = BCryptSetProperty(pAlg, BCRYPT_ECC_CURVE_NAME, BCRYPT_ECC_CURVE_25519, sizeof BCRYPT_ECC_CURVE_25519, 0);
  if (status != ERROR_SUCCESS)
    goto err;
  union
  {
    struct
    {
      BCRYPT_KEY_BLOB blb;
      char key[ED25519_KEY_LENGTH];
    };
    uchar start[1];
  } winkey;
  static_assert(sizeof winkey == sizeof winkey.blb + ED25519_KEY_LENGTH);

  memcpy(winkey.key, private_key, ED25519_KEY_LENGTH);
  winkey.blb.Magic= BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC;

  func = "BCryptImportKeyPair";
  status = BCryptImportKeyPair(pAlg, NULL, BCRYPT_PRIVATE_KEY_BLOB, &hbKey, winkey.start, sizeof winkey, 0);
  if (status != ERROR_SUCCESS)
    goto err;

  ulong written=0;
  func = "BCryptSignHash";
  status = BCryptSignHash(hbKey, NULL, (PUCHAR)response, (ULONG)response_len, signature, ED25519_SIG_LENGTH, &written, 0);
  if (status != ERROR_SUCCESS)
    goto err;
  result = 0;
cleanup:
  return result;
err:
  fprintf(stderr, "%s failed: 0x%08x\n", func, status);
  goto cleanup;
#else /* HAVE_GNUTLS */
  ed25519_sha512_public_key((uint8_t*)public_key, (uint8_t*)private_key);
  ed25519_sha512_sign((uint8_t*)public_key, (uint8_t*)private_key,
                      response_len, (uint8_t*)response, (uint8_t*)signature);
  return 0;
#endif
}

int random_bytes(uchar *buf, int num)
{
  HCRYPTPROV hProv;
  if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    return 1;

  if (!CryptGenRandom(hProv, num, buf))
  {
    CryptReleaseContext(hProv, 0);
    return 1;
  }

  CryptReleaseContext(hProv, 0);
  return 0;
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
  struct Passwd_in_memory *params;
  int pkt_len;
  char *newpw;
  uchar priv_key[ED25519_KEY_LENGTH];
  size_t pwlen= strlen(mysql->passwd);

  pkt_len= vio->read_packet(vio, (uchar**)(&serv_scramble));
  if (pkt_len != CHALLENGE_SCRAMBLE_LENGTH)
    return CR_SERVER_HANDSHAKE_ERR;

  memcpy(signed_msg.server_scramble, serv_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  if (vio->write_packet(vio, 0, 0) != 0) // empty packet = "need salt"
    return CR_ERROR;

  pkt_len= vio->read_packet(vio, (uchar**)&params);
  if (pkt_len != 2 + CHALLENGE_SALT_LENGTH)
    return CR_SERVER_HANDSHAKE_ERR;
  if (params->algorithm != 'P')
    return CR_AUTH_PLUGIN_ERR;
  if (params->iterations > 3)
    return CR_AUTH_PLUGIN_ERR;

  random_bytes(signed_msg.response.client_scramble, CHALLENGE_SCRAMBLE_LENGTH);

  if (compute_derived_key(mysql->passwd, pwlen, params, priv_key))
    return CR_AUTH_PLUGIN_ERR;

  if (ed25519_sign(signed_msg.start, CHALLENGE_SCRAMBLE_LENGTH * 2,
                   priv_key, signed_msg.response.signature, params->pub_key))
    return CR_AUTH_PLUGIN_ERR;

  /* save for the future hash_password() call */
  if ((newpw= realloc(mysql->passwd, pwlen + 1 + sizeof(*params))))
  {
    memcpy(newpw + pwlen + 1, params, sizeof(*params));
    mysql->passwd= newpw;
  }

  if (vio->write_packet(vio, signed_msg.response.start,
                        sizeof signed_msg.response) != 0)
    return CR_ERROR;

  return CR_OK;
}

static int hash_password(MYSQL *mysql, unsigned char *out, size_t *outlen)
{
  if (*outlen < sizeof(struct Passwd_in_memory))
    return 1;
  *outlen= sizeof(struct Passwd_in_memory);

  /* use the cached value */
  memcpy(out, mysql->passwd + strlen(mysql->passwd) + 1,
         sizeof(struct Passwd_in_memory));
  return 0;
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
  hash_password,
mysql_end_client_plugin;
