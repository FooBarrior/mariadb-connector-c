#include <openssl/evp.h>
#include <openssl/err.h>
#include "errmsg.h"
#include "ma_global.h"
constexpr size_t CHALLENGE_SCRAMBLE_LENGTH= SCRAMBLE_LENGTH;
constexpr size_t CHALLENGE_SALT_LENGTH= 32; // Double the NIST recommendation
constexpr size_t PBKDF2_HASH_LENGTH= 32;
constexpr size_t ED25519_SIG_LENGTH= 64;
constexpr size_t ED25519_KEY_LENGTH= 32;
constexpr size_t CLIENT_RESPONSE_LENGTH= CHALLENGE_SCRAMBLE_LENGTH * 2
                                         + ED25519_SIG_LENGTH;
constexpr size_t SERVER_PARAMETERS_LENGTH= 2 + CHALLENGE_SALT_LENGTH
                                           + CHALLENGE_SCRAMBLE_LENGTH;

struct Server_params
{
  uchar hash;
  int iterations;
  const uchar *salt;
  const uchar *scramble;
};


struct alignas(1) Server_challenge
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

static_assert(sizeof(Server_challenge) == 2 + CHALLENGE_SALT_LENGTH,
              "Server_challenge is not aligned.");

struct alignas(1) Client_signed_response
{
  union {
    struct {
      uchar server_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      uchar signature[ED25519_SIG_LENGTH];
    };
    uchar start[1];
  };
};

static_assert(sizeof(Client_signed_response) == CLIENT_RESPONSE_LENGTH,
              "Client_signed_response is not aligned.");

