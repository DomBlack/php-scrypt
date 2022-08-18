/*-
 * Copyright 2012 Dominic Black
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_version.h"
#include "zend_exceptions.h"

#ifdef PHP_WIN32
#include "zend_config.w32.h"
#endif

#include "ext/hash/php_hash.h"
#include "php_scrypt_utils.h"
#include "php_scrypt.h"
#include "crypto/crypto_scrypt.h"
#include "crypto/params.h"
#if PHP_MAJOR_VERSION >= 8
#include "php_scrypt_arginfo.h"
#else
#include "php_scrypt_legacy_arginfo.h"
#endif
#include "math.h"

#if PHP_VERSION_ID < 80000
#define RETURN_THROWS() do { ZEND_ASSERT(EG(exception)); (void) return_value; return; } while (0)
#endif

typedef size_t strsize_t;

static const zend_module_dep scrypt_deps[] = {
	ZEND_MOD_REQUIRED("hash")
	ZEND_MOD_END
};

zend_module_entry scrypt_module_entry = {
	STANDARD_MODULE_HEADER_EX,
	NULL,
	scrypt_deps,
	PHP_SCRYPT_EXTNAME,
	ext_functions,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	PHP_SCRYPT_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SCRYPT
ZEND_GET_MODULE(scrypt)
#endif

/*
 * Returns the scrypt hash for the given password.
 *
 * Where;
 *     string $password The user's password
 *     string $salt The user's salt
 *     long   $N The CPU difficultly (must be a power of 2, greater than 1)
 *     int    $r The memory difficulty
 *     int    $p The parallel difficulty
 *     int    $keyLength The length of hash
 *
 * The parameters $r, $p must satisfy; $r * $p < 2^30
 * The parameter $keyLength must satisfy; $keyLength <= (2^32 - 1) * 32.
 * The parameter $N must be a power of 2 greater than 1.
 *
 * This function will return a hex encoded version of the binary hash.
 */
PHP_FUNCTION(scrypt)
{
	/* Variables for PHP's parameters */
	unsigned char *password;
	strsize_t password_len;

	unsigned char *salt;
	strsize_t salt_len;

	long phpN;
	long phpR;
	long phpP;
	long keyLength;

	zend_bool raw_output;

	/* Casted variables for scrypt */
	uint64_t cryptN;
	uint32_t cryptR;
	uint32_t cryptP;
	int castError;

	/* Output variables */
	char *hex;
	unsigned char *buf;

	int result;

	/* Get the parameters for this call */
	raw_output = 0;
	if (zend_parse_parameters_throw(
			ZEND_NUM_ARGS() TSRMLS_CC, "ssllll|b",
			&password, &password_len, &salt, &salt_len,
			&phpN, &phpR, &phpP, &keyLength, &raw_output
		) == FAILURE)
	{
		RETURN_THROWS();
	}

	/* Checks on the parameters */

	castError = 0;
	cryptN = clampAndCast64(3, "N", phpN, 1);
	if (EG(exception)) {
		RETURN_THROWS();
	}
	cryptR = clampAndCast32(4, "r", phpR, 0);
	if (EG(exception)) {
		RETURN_THROWS();
	}
	cryptP = clampAndCast32(5, "p", phpP, 0);
	if (EG(exception)) {
		RETURN_THROWS();
	}

	if (isPowerOfTwo(cryptN) != 0) {
#if PHP_VERSION_ID >= 80000
		zend_argument_error(NULL, 3, "must be a power of 2");
#else
		zend_throw_error(zend_ce_error, "scrypt(): Argument #3 ($N) must be a power of 2");
#endif
		RETURN_THROWS();
	}

	if (keyLength < 16) {
#if PHP_VERSION_ID >= 80000
		zend_argument_error(NULL, 6, "must be greater than or equal to 16");
#else
		zend_throw_error(zend_ce_error, "scrypt(): Argument #6 ($key_length) must be greater than or equal to 16");
#endif
		RETURN_THROWS();
	}

	if (keyLength > (powl(2, 32) - 1) * 32) {
#if PHP_VERSION_ID >= 80000
		zend_argument_error(NULL, 6, "must be less than or equal to (2^32 - 1) * 32");
#else
		zend_throw_error(zend_ce_error, "scrypt(): Argument #6 ($key_length) must be less than or equal to (2^32 - 1) * 32");
#endif
		RETURN_THROWS();
	}

	/* Allocate the memory for the output of the key */
	buf = (unsigned char*)safe_emalloc(1, keyLength, 1);

	/* Call the scrypt function */
	result = crypto_scrypt(
		password, password_len, salt, salt_len, /* Input */
		cryptN, cryptR, cryptP, /* Settings */
		buf, keyLength /* Output */
	);

	/* Check the crypto returned the hash we wanted. */
	if (result != 0) {
		efree(buf);
		RETURN_FALSE;
	}

	if (!raw_output) {
		/* Encode the output in hex */
		hex = (char*) safe_emalloc(2, keyLength, 1);
		php_hash_bin2hex(hex, buf, keyLength);
		efree(buf);
		hex[keyLength*2] = '\0';
		RETVAL_STRINGL(hex, keyLength * 2);
		efree(hex);
	} else {
		buf[keyLength] = '\0';
		RETVAL_STRINGL((char *)buf, keyLength);
		efree(buf);
	}
}

/*
 * Returns N, r and p picked automatically for use with the scrypt function.
 *
 * Where;
 *     long   $maxMem  Maximum amount of memory to use
 *     double $memFrac Maximum fraction of available memory to use
 *     double $maxTime Maximum CPU time to use
 */
PHP_FUNCTION(scrypt_pickparams)
{
	long maxmem;
	double memfrac, maxtime;

	int cryptN;
	uint32_t cryptR;
	uint32_t cryptP;

	long phpN, phpP, phpR;

	int rc;

	/* Get the parameters for this call */
	if (zend_parse_parameters_throw(
			ZEND_NUM_ARGS() TSRMLS_CC, "ldd",
			&maxmem, &memfrac, &maxtime
		) == FAILURE)
	{
		RETURN_THROWS();
	}

	if (maxmem < 0) {
#if PHP_VERSION_ID >= 80000
		zend_argument_error(NULL, 1, "must be greater than or equal to 0");
#else
		zend_throw_error(zend_ce_error, "scrypt_pickparams(): Argument #1 ($max_memory) must be greater than or equal to 0");
#endif
		RETURN_THROWS();
	}

	if (memfrac < 0) {
#if PHP_VERSION_ID >= 80000
		zend_argument_error(NULL, 2, "must be greater than or equal to 0");
#else
		zend_throw_error(zend_ce_error, "scrypt_pickparams(): Argument #2 ($memory_fraction) must be greater than or equal to 0");
#endif
		RETURN_THROWS();
	}

	if (maxtime < 0) {
#if PHP_VERSION_ID >= 80000
		zend_argument_error(NULL, 3, "must be greater than or equal to 0");
#else
		zend_throw_error(zend_ce_error, "scrypt_pickparams(): Argument #3 ($max_time) must be greater than or equal to 0");
#endif
		RETURN_THROWS();
	}

	rc = pickparams((size_t) maxmem, memfrac, maxtime, &cryptN, &cryptR, &cryptP);

	if (rc != 0) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Could not determine scrypt parameters.");
		RETURN_FALSE;
	}

	phpN = (long) cryptN;
	phpR = (long) cryptR;
	phpP = (long) cryptP;

	array_init(return_value);
	add_assoc_long(return_value, "n", phpN);
	add_assoc_long(return_value, "r", phpR);
	add_assoc_long(return_value, "p", phpP);
}
