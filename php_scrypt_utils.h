/*-
 * Copyright 2012 Dominic Black
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef PHP_SCRYPT_UTILS_H
#define PHP_SCRYPT_UTILS_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef PHP_WIN32
#include "zend_config.w32.h"
#endif
#include "php.h"
#ifdef PHP_WIN32
# include "win32/php_stdint.h"
#else
# include <stdint.h>
#endif

/*
 * Casts a long into a uint64_t.
 *
 * Throws a php error if the value is out of bounds
 * and will return 0. The error varaible will be set to 1, otherwise
 * left intact
 */
uint64_t
clampAndCast64(const char *variableName, long value, int *error, long min);

/*
 * Casts a long into a uint32_t.
 *
 * Throws a php error if the value is out of bounds
 * and will return 0. The error varaible will be set to 1, otherwise
 * left intact
 */
uint32_t
clampAndCast32(const char *variableName, long value, int *error, long min);

/*
 * Checks if the givn number is a power of two
 */
uint64_t
isPowerOfTwo (uint64_t N);

#endif
