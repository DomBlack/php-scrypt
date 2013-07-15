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
class Password
{
    /**
     * @var int The key length
     */
    private static $_keyLength = 32;

    /**
     * Generates a random salt
     *
     * @param int $length The length of the salt
     *
     * @return string The salt
     */
    public static function generateSalt($length = 8)
    {
        $salt = '';
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%&*?';
        $num = strlen($chars) - 1;

        for ($i = 0; $i < $length; $i++) {
            $salt .= $chars[mt_rand(0, $num)];
        }

        return $salt;
    }

    /**
     * Create a password hash
     *
     * @param string $password The clear text password
     * @param string $salt     The salt to use, or null to generate a random one
     * @param int    $N        The CPU difficultly (must be a power of 2,  > 1)
     * @param int    $r        The memory difficultly
     * @param int    $p        The parallel difficultly
     *
     * @return string The hashed password
     */
    public static function hash($password, $salt = false, $N = 16384, $r = 8, $p = 1)
    {
        if ($salt === false) {
            $salt = self::generateSalt();
        } else {
            //Remove dollar signs from the salt, as we use that as a separator.
            $salt = str_replace('$', '', $salt);
        }

        $hash = scrypt($password, $salt, $N, $r, $p, self::$_keyLength);

        return $N.'$'.$r.'$'.$p.'$'.$salt.'$'.$hash;
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
        if (!strlen($hash)) {
            return false;
        }

        list($N, $r, $p, $salt, $hash) = explode('$', $hash);

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
     *
     * Compare two strings to avoid timing attacks
     *
     * C function memcmp() internally used by PHP, exits as soon as a difference
     * is found in the two buffers. That makes possible of leaking
     * timing information useful to an attacker attempting to iteratively guess
     * the unknown string (e.g. password).
     *
     * @param  string $expected
     * @param  string $actual
     *
     * @return boolean If the two strings match.
     */
    public static function compareStrings($expected, $actual)
    {
        $expected     = (string) $expected;
        $actual       = (string) $actual;
        $lenExpected  = strlen($expected);
        $lenActual    = strlen($actual);
        $len          = min($lenExpected, $lenActual);

        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($expected[$i]) ^ ord($actual[$i]);
        }
        $result |= $lenExpected ^ $lenActual;

        return ($result === 0);
    }
}
