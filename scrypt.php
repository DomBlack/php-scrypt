<?php
/**
 * This file contains wrapper and helper classes for the scrypt extension.
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
 * This class abstracts away from
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
     * @var An application pepper (set to null for none)
     */
    private static $_pepper = 'qi$1IeXl?$Oa_ia7';

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
        $possibleChars = '0123456789abcdefghijklmnopqrstuvwxyz';
        $noOfChars = strlen($possibleChars) - 1;

        for ($i = 0; $i < $length; $i++) {
            $salt .= $possibleChars[mt_rand(0, $noOfChars)];
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
    public static function hash(
        $password, $salt = false, $N = 16384, $r = 8, $p = 1
    ) {
        if ($salt === false) {
            $salt = self::generateSalt();
        } else {
            //Remove dollar signs from the salt, as we use that as a separator.
            $salt = str_replace('$', '', $salt);
        }

        $hash = scrypt($password, self::$_pepper.$salt, $N, $r, $p, self::$_keyLength);

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
        list($N, $r, $p, $salt, $hash) = explode('$', $hash);

        $calculated = scrypt(
            $password, self::$_pepper.$salt,
            $N, $r, $p,
            self::$_keyLength
        );

        return ($calculated == $hash);
    }
}

?>