/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: ea5f25cdf40271f96836b23cdda89954e4c2a479 */

ZEND_BEGIN_ARG_INFO_EX(arginfo_scrypt, 0, 0, 6)
	ZEND_ARG_INFO(0, password)
	ZEND_ARG_INFO(0, salt)
	ZEND_ARG_INFO(0, N)
	ZEND_ARG_INFO(0, r)
	ZEND_ARG_INFO(0, p)
	ZEND_ARG_INFO(0, key_length)
	ZEND_ARG_INFO(0, raw_output)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_scrypt_pickparams, 0, 0, 3)
	ZEND_ARG_INFO(0, max_memory)
	ZEND_ARG_INFO(0, memory_fraction)
	ZEND_ARG_INFO(0, max_time)
ZEND_END_ARG_INFO()


ZEND_FUNCTION(scrypt);
ZEND_FUNCTION(scrypt_pickparams);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(scrypt, arginfo_scrypt)
	ZEND_FE(scrypt_pickparams, arginfo_scrypt_pickparams)
	ZEND_FE_END
};
