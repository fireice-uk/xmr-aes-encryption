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

#pragma once

#include <stdint.h>
#include <assert.h>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#pragma GCC push_options
#pragma GCC target ("sse2")
#pragma GCC push_options
#pragma GCC target ("aes")
#include <x86intrin.h>
#endif

#include "keccak.h"

// Implemented in soft_aes.c
extern "C" __m128i soft_aesenc(__m128i in, __m128i key);
extern "C" __m128i soft_aesenclast(__m128i in, __m128i key);
extern "C" __m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);
extern "C" void s_memzero(void* p, size_t len);

// Implemented in random.c
extern "C" void generate_random_bytes(uint8_t* data, size_t len);

inline void cpuid(uint32_t eax, int32_t ecx, int32_t val[4])
{
	val[0] = 0;
	val[1] = 0;
	val[2] = 0;
	val[3] = 0;

#ifdef _MSC_VER
	__cpuidex(val, eax, ecx);
#else
	__cpuid_count(eax, ecx, val[0], val[1], val[2], val[3]);
#endif
}

class key_128
{
public:
	// NOTE!!! no const on constructors, we will wipe the source
	key_128(uint8_t* from_mem)
	{
		memcpy(key_data, from_mem, 16);
		s_memzero(from_mem, 16);
	}

	key_128(char* from_pass, uint64_t salt)
	{
		pbkdf2_keccak_128(from_pass, salt, key_data);
		s_memzero(from_pass, strlen(from_pass));
	}

	key_128()
	{
		generate_random_bytes(key_data, 16);
	}

	~key_128()
	{
		s_memzero(key_data, 16);
	}

	//Prevent bad ideas
	key_128(const key_128& other) = delete;
	key_128(key_128&& other) = delete;
	key_128& operator= (const key_128& other) = delete;
	key_128& operator= (key_128&& other) = delete;

	inline const uint8_t* data_ptr() const { return key_data; }
	inline __m128i data_reg() const { return _mm_load_si128((const __m128i *) key_data); }

private:
	alignas(16) uint8_t key_data[16];
};

class aes_ctr
{
protected:
	// Encryption mode
	aes_ctr(char* from_pass, uint64_t salt, const uint8_t* nonce) : key(from_pass, salt)
	{
		check_aes();
		ctr = _mm_loadu_si128((const __m128i*)nonce);
	}

	// PRNG mode, ctr_low = 0
	aes_ctr(uint8_t* from_mem, uint64_t ctr_high) : key(from_mem)
	{
		check_aes();
		ctr = _mm_set_epi64x(ctr_high, 0);
	}

	typedef __m128i (aes_ctr::*encrypt_fun)();
	encrypt_fun encfun = nullptr;

private:
	void check_aes()
	{
		constexpr int AESNI_BIT = 1 << 25;
		int32_t cpu_info[4];
		cpuid(1, 0, cpu_info);
		if((cpu_info[2] & AESNI_BIT) != 0)
			encfun = &aes_ctr::aes128_encrypt_block;
		else
			encfun = &aes_ctr::soft_aes128_encrypt_block;
	}

	template <uint8_t rcon>
	inline __m128i aes128_keyexpand(__m128i key)
	{
		__m128i keygened = _mm_aeskeygenassist_si128(key, rcon);
		keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));

		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		return _mm_xor_si128(key, keygened);
	}

	inline __m128i soft_aes128_keyexpand(__m128i key, uint8_t rcon)
	{
		__m128i keygened = soft_aeskeygenassist(key, rcon);
		keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));

		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
		return _mm_xor_si128(key, keygened);
	}

	__m128i aes128_encrypt_block();
	__m128i soft_aes128_encrypt_block();

	key_128 key;
	__m128i ctr;
};

class aes_ctr_cipher : public aes_ctr
{
public:
	// NOTE!!! no const on constructors, we will wipe the source
	aes_ctr_cipher(char* from_pass, uint64_t salt, const uint8_t* nonce) : aes_ctr(from_pass, salt, nonce)
	{
	}

	inline void encrypt_data(uint8_t* block)
	{
		_mm_storeu_si128((__m128i*) block,
			_mm_xor_si128(_mm_loadu_si128((const __m128i *) block), (*this.*encfun)()));
	}
};

class aes_ctr_prng : public aes_ctr
{
public:
	aes_ctr_prng(uint8_t* seed, uint64_t ctr_high) : aes_ctr(seed, ctr_high), bits_used(0)
	{
		_mm_store_si128((__m128i*)block, (*this.*encfun)());
	}

	size_t get_random(size_t bit_count);

private:
	alignas(16) uint8_t block[16];
	size_t bits_used;
};
