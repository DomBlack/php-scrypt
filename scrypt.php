<?php

/**
 * This file contains an example helper classes for the php-scrypt extension.
 *
 * As with all cryptographic code; it is recommended that you use a tried and
 * tested library which uses this library; rather than rolling your own.
 *
 * PHP version 5
 *
 * @category Security
 * @package  Scrypt
 * @author   Dominic Black <thephenix@gmail.com>
 * @license  http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link     http://github.com/DomBlack/php-scrypt
 */

/**
 * This class abstracts away from scrypt module, allowing for easy use.
 *
 * You can create a new hash for a password by calling Password::hash($password)
 *
 * You can check a password by calling Password::check($password, $hash)
 *
 * @category Security
 * @package  Scrypt
 * @author   Dominic Black <thephenix@gmail.com>
 * @license  http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link     http://github.com/DomBlack/php-scrypt
 */
abstract class Password
{

    /**
     *
     * @var int The key length
     */
    private static $_keyLength = 32;

    /**
     * Get the byte-length of the given string
     *
     * @param string $str Input string
     *
     * @return int
     */
    protected static function strlen( $str ) {
        static $isShadowed = null;

        if ($isShadowed === null) {
            $isShadowed = extension_loaded('mbstring') &&
                ini_get('mbstring.func_overload') & 2;
        }

        if ($isShadowed) {
            return mb_strlen($str, '8bit');
        } else {
            return strlen($str);
        }
    }

    /**
     * Generates a random salt
     *
     * @param int $length The length of the salt
     *
     * @return string The salt
     */
    public static function generateSalt($length = 8)
    {
        $buffer = '';
        $buffer_valid = false;
        if (function_exists('mcrypt_create_iv') && !defined('PHALANGER')) {
            $buffer = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($buffer) {
                $buffer_valid = true;
            }
        }
        if (!$buffer_valid && function_exists('openssl_random_pseudo_bytes')) {
            $cryptoStrong = false;
            $buffer = openssl_random_pseudo_bytes($length, $cryptoStrong);
            if ($buffer && $cryptoStrong) {
                $buffer_valid = true;
            }
        }
        if (!$buffer_valid && is_readable('/dev/urandom')) {
            $f = fopen('/dev/urandom', 'r');
            $read = static::strlen($buffer);
            while ($read < $length) {
                $buffer .= fread($f, $length - $read);
                $read = static::strlen($buffer);
            }
            fclose($f);
            if ($read >= $length) {
                $buffer_valid = true;
            }
        }
        if (!$buffer_valid || static::strlen($buffer) < $length) {
            $bl = static::strlen($buffer);
            for ($i = 0; $i < $length; $i++) {
                if ($i < $bl) {
                    $buffer[$i] = $buffer[$i] ^ chr(mt_rand(0, 255));
                } else {
                    $buffer .= chr(mt_rand(0, 255));
                }
            }
        }
        $salt = str_replace(array('+', '$'), array('.', ''), base64_encode($buffer));

        return $salt;
    }

    /**
     * Create a password hash
     *
     * @param string $password The clear text password
     * @param string $salt     The salt to use, or null to generate a random one
     * @param int    $N        The CPU difficultly (must be a power of 2, > 1)
     * @param int    $r        The memory difficultly
     * @param int    $p        The parallel difficultly
     *
     * @return string The hashed password
     */
    public static function hash($password, $salt = false, $N = 16384, $r = 8, $p = 1)
    {
        if ($N == 0 || ($N & ($N - 1)) != 0) {
            throw new \InvalidArgumentException("N must be > 0 and a power of 2");
        }

        if ($N > PHP_INT_MAX / 128 / $r) {
            throw new \InvalidArgumentException("Parameter N is too large");
        }

        if ($r > PHP_INT_MAX / 128 / $p) {
            throw new \InvalidArgumentException("Parameter r is too large");
        }

        if ($salt === false) {
            $salt = self::generateSalt();
        } else {
            // Remove dollar signs from the salt, as we use that as a separator.
            $salt = str_replace(array('+', '$'), array('.', ''), base64_encode($salt));
        }

        $hash = scrypt($password, $salt, $N, $r, $p, self::$_keyLength);

        return $N . '$' . $r . '$' . $p . '$' . $salt . '$' . $hash;
    }

    /**
     * Check a clear text password against a hash
     *
     * @param string $password The clear text password
     * @param string $hash     The hashed password
     *
     * @return boolean If the clear text matches
     */
    public static function check($password, $hash)
    {
        // Is there actually a hash?
        if (!$hash) {
            return false;
        }

        list ($N, $r, $p, $salt, $hash) = explode('$', $hash);

        // No empty fields?
        if (empty($N) or empty($r) or empty($p) or empty($salt) or empty($hash)) {
            return false;
        }

        // Are numeric values numeric?
        if (!is_numeric($N) or !is_numeric($r) or !is_numeric($p)) {
            return false;
        }

        $calculated = scrypt($password, $salt, $N, $r, $p, self::$_keyLength);

        // Use compareStrings to avoid timeing attacks
        return self::compareStrings($hash, $calculated);
    }

    /**
     * Zend Framework (http://framework.zend.com/)
     *
     * @link      http://github.com/zendframework/zf2 for the canonical source repository
     * @copyright Copyright (c) 2005-2013 Zend Technologies USA Inc. (http://www.zend.com)
     * @license   http://framework.zend.com/license/new-bsd New BSD License
     *
     * Compare two strings to avoid timing attacks
     *
     * C function memcmp() internally used by PHP, exits as soon as a difference
     * is found in the two buffers. That makes possible of leaking
     * timing information useful to an attacker attempting to iteratively guess
     * the unknown string (e.g. password).
     *
     * @param string $expected
     * @param string $actual
     *
     * @return boolean If the two strings match.
     */
    public static function compareStrings($expected, $actual)
    {
        $expected    = (string) $expected;
        $actual      = (string) $actual;
        $lenExpected = static::strlen($expected);
        $lenActual   = static::strlen($actual);
        $len         = min($lenExpected, $lenActual);

        $result = 0;
        for ($i = 0; $i < $len; $i ++) {
            $result |= ord($expected[$i]) ^ ord($actual[$i]);
        }
        $result |= $lenExpected ^ $lenActual;

        return ($result === 0);
    }
}
