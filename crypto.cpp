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

#include "crypto.h"
#include <algorithm>

size_t aes_ctr_prng::get_random(size_t bit_count)
{
	assert(bit_count <= 64);
	size_t output = 0;
	size_t output_bits = 0;

	while(bit_count > 0)
	{
		assert(bits_used <= 128);
		if(bits_used >= 128)
		{
			_mm_store_si128((__m128i*)block, (*this.*encfun)());
			bits_used = 0;
		}

		size_t idx = bits_used / 8;
		size_t take = std::min(8 - bits_used % 8, bit_count);
		size_t take_mask = 0xFF >> (8-take);

		size_t data = (block[idx] >> (bits_used % 8)) & take_mask;
		output |= data << output_bits;

		output_bits += take;
		bits_used += take;
		bit_count -= take;
	}

	return output;
}

__m128i aes_ctr::aes128_encrypt_block()
{
	__m128i rkey = key.data_reg();
	__m128i txt = _mm_xor_si128(ctr, rkey); // round 0
	ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1));

	rkey = aes128_keyexpand<0x01>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 1

	rkey = aes128_keyexpand<0x02>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 2

	rkey = aes128_keyexpand<0x04>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 3

	rkey = aes128_keyexpand<0x08>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 4

	rkey = aes128_keyexpand<0x10>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 5

	rkey = aes128_keyexpand<0x20>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 6

	rkey = aes128_keyexpand<0x40>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 7

	rkey = aes128_keyexpand<0x80>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 8

	rkey = aes128_keyexpand<0x1B>(rkey);
	txt = _mm_aesenc_si128(txt, rkey); // round 9

	rkey = aes128_keyexpand<0x36>(rkey);
	txt = _mm_aesenclast_si128(txt, rkey); // round 10

	return txt;
}

__m128i aes_ctr::soft_aes128_encrypt_block()
{
	__m128i rkey = key.data_reg();
	__m128i txt = _mm_xor_si128(ctr, rkey); // round 0
	ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1));

	rkey = soft_aes128_keyexpand(rkey, 0x01);
	txt = soft_aesenc(txt, rkey); // round 1

	rkey = soft_aes128_keyexpand(rkey, 0x02);
	txt = soft_aesenc(txt, rkey); // round 2

	rkey = soft_aes128_keyexpand(rkey, 0x04);
	txt = soft_aesenc(txt, rkey); // round 3

	rkey = soft_aes128_keyexpand(rkey, 0x08);
	txt = soft_aesenc(txt, rkey); // round 4

	rkey = soft_aes128_keyexpand(rkey, 0x10);
	txt = soft_aesenc(txt, rkey); // round 5

	rkey = soft_aes128_keyexpand(rkey, 0x20);
	txt = soft_aesenc(txt, rkey); // round 6

	rkey = soft_aes128_keyexpand(rkey, 0x40);
	txt = soft_aesenc(txt, rkey); // round 7

	rkey = soft_aes128_keyexpand(rkey, 0x80);
	txt = soft_aesenc(txt, rkey); // round 8

	rkey = soft_aes128_keyexpand(rkey, 0x1B);
	txt = soft_aesenc(txt, rkey); // round 9

	rkey = soft_aes128_keyexpand(rkey, 0x36);
	txt = soft_aesenclast(txt, rkey); // round 10

	return txt;
}

int main()
{
}
