/*
   Copyright (c) 2024, MariaDB Corporation.

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

constexpr size_t CHALLENGE_SCRAMBLE_LENGTH= 32;
constexpr size_t CHALLENGE_SALT_LENGTH= 32; // Double the NIST recommendation
constexpr size_t ED25519_SIG_LENGTH= 64;
constexpr size_t ED25519_KEY_LENGTH= 32;
constexpr size_t PBKDF2_HASH_LENGTH= ED25519_KEY_LENGTH;
constexpr size_t CLIENT_RESPONSE_LENGTH= CHALLENGE_SCRAMBLE_LENGTH
                                         + ED25519_SIG_LENGTH;


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
      uchar client_scramble[CHALLENGE_SCRAMBLE_LENGTH];
      uchar signature[ED25519_SIG_LENGTH];
    };
    uchar start[1];
  };
};

static_assert(sizeof(Client_signed_response) == CLIENT_RESPONSE_LENGTH,
              "Client_signed_response is not aligned.");

