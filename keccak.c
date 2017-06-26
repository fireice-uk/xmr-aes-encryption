/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Parts of this file are originally copyright (c) 2015 Markku-Juhani O. Saarinen
#include "keccak.h"

#ifndef _MSC_VER
static inline  __attribute__((always_inline)) uint64_t _rotl64(uint64_t x, unsigned n)
{
	return (x << n) | (x >> (64 - n));
}
#endif // _MSC_VER

// update the state with given number of rounds

void keccak_keccakf(uint64_t st[25])
{
    // constants
    const uint64_t keccakf_rndc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    const int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    const int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    // variables
    int i, j, r;
    uint64_t t, bc[5];

    // actual iteration
    for (r = 0; r < 24; r++) {

        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ _rotl64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = _rotl64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        //  Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        //  Iota
        st[0] ^= keccakf_rndc[r];
    }
}

// update state with more data
void keccak_update(keccak_ctx *c, const void *data, size_t len)
{
    size_t i, j;

    j = c->pt;
    for (i = 0; i < len; i++) {
        c->st.b[j++] ^= ((const uint8_t *) data)[i];
        if (j >= 136) {
            keccak_keccakf(c->st.q);
            j = 0;
        }
    }
    c->pt = j;
}

// finalize and output a hash
void keccak_final(keccak_ctx *c, void *md)
{
    c->st.b[c->pt] ^= 0x01;
    c->st.b[135] ^= 0x80;
    keccak_keccakf(c->st.q);

    memcpy(md, c->st.b, 32);
}

void *keccak(const void *in, size_t inlen, void *md)
{
    keccak_ctx keccak = { 0 };

    keccak_update(&keccak, in, inlen);
    keccak_final(&keccak, md);

    return md;
}

void hmac_keccak(const uint8_t* in, size_t inlen, const uint8_t* key, size_t keylen, void* md)
{
    keccak_ctx ctx = { 0 };
    uint8_t hash[32];

    //Slightly modified keccak_update, always do a full round
    for(size_t i=0; i < 136; i++)
    {
        if(i < keylen)
            ctx.st.b[i] = key[i] ^ 0x36;
        else
            ctx.st.b[i] = 0x36;
    }
    keccak_keccakf(ctx.st.q);

    //Feeed in the message
    ctx.pt = 0;
    keccak_update(&ctx, in, inlen);
    keccak_final(&ctx, hash);

    memset(&ctx, 0, sizeof(keccak_ctx));
    for(size_t i=0; i < 136; i++)
    {
        if(i < keylen)
            ctx.st.b[i] = key[i] ^ 0x5c;
        else
            ctx.st.b[i] = 0x5c;
    }
    keccak_keccakf(ctx.st.q);

    ctx.pt = 0;
    keccak_update(&ctx, hash, 32);
    keccak_final(&ctx, md);
}

#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

void pbkdf2_keccak_128(const char* pwd, uint64_t salt, void* dk)
{
    uint64_t U[4], Un[4]; //Hash outputs
    uint32_t iter = SWAP_UINT32(1);
    uint8_t saltiter[12]; //salt with iter for the first hmac
    size_t pwdlen = strlen(pwd);

    memcpy(saltiter, &salt, sizeof(salt));
    memcpy(saltiter+8, &iter, sizeof(iter));

    hmac_keccak((uint8_t*)pwd, pwdlen, saltiter, 12, U);
    for(size_t n = 2; n < 10000; n++)
    {
        hmac_keccak((uint8_t*)pwd, pwdlen, (uint8_t*)U, 32, Un);

        U[0] ^= Un[0];
        U[1] ^= Un[1];
        U[2] ^= Un[2];
        U[3] ^= Un[3];
    }

    memcpy(dk, U, 16);
}
