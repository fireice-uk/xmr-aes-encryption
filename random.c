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

// Parts of this file are originally copyright (c) 2014-2017, The Monero Project
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(_WIN32)

#include <windows.h>
#include <wincrypt.h>

void generate_system_random_bytes(size_t n, uint8_t* result)
{
	HCRYPTPROV prov;
	if(CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT) == FALSE)
		abort();

	if(CryptGenRandom(prov, (DWORD)n, result) == FALSE)
		abort();

	if(CryptReleaseContext(prov, 0) == FALSE)
		abort();
}

#else

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void generate_system_random_bytes(size_t n, uint8_t* result)
{
	int fd;
	if ((fd = open("/dev/urandom", O_RDONLY | O_NOCTTY | O_CLOEXEC)) < 0)
		err(EXIT_FAILURE, "open /dev/urandom");

	while(true)
	{
		ssize_t res = read(fd, result, n);
		if((size_t) res == n)
			break;

		if (res < 0)
		{
			if (errno != EINTR)
				err(EXIT_FAILURE, "read /dev/urandom");
		}
		else if (res == 0)
		{
			err(EXIT_FAILURE, "read /dev/urandom: end of file");
		}
		else
		{
			result += (size_t) res;
			n -= (size_t) res;
		}
	}

	if(close(fd) < 0)
		err(EXIT_FAILURE, "close /dev/urandom");
}
#endif

void generate_random_bytes(uint8_t* data, size_t len)
{
	if(len < sizeof(uint64_t))
	{
		generate_system_random_bytes(len, data);
		return;
	}

	*((uint64_t*)data) = 0;

	generate_system_random_bytes(len, data);

	if(*((uint64_t*)data) == 0)
		abort();
}

void s_memzero(void* p, size_t len)
{
#if defined(_WIN32)
	SecureZeroMemory(p, len);
#else
	volatile uint8_t * _p = p;
	while (len--) *_p++ = 0;
#endif // defined
}
