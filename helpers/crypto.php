<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined( '_JEXEC' ) or die;

class BFStopTokenGenerator {

	const HexLetter = '0123456789abcdef';

	private function getRandHexLetter() {
		$idx = mt_rand(0,15);
		return substr(self::HexLetter, $idx, 1);
	}

	private function getRandToken($length) {
		$token = '';
		for ($i=0; $i<$length; ++$i) {
			$token .= self::getRandHexLetter();
		}
		return $token;
	}

	public function getToken($logger)
	{
		$length = 64;
		$strongCrypto = false;
		$token = '';
		if (function_exists('openssl_random_pseudo_bytes') ||
			is_callable('openssl_random_pseudo_bytes'))
		{
			$logger->log('Using OpenSSL random number generator for token', JLog::DEBUG);
			$token = openssl_random_pseudo_bytes($length, $strongCrypto);
			if (!$strongCrypto)
			{
				$logger->log('Your servers openssl implementation does not use strong cryptographics!', JLog::WARNING);
			}
		}
		if (!$strongCrypto &&
			function_exists('mcrypt_create_iv') &&
			(strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN' ||
			version_compare(phpversion(), '5.3.7') > 0) )
		{
			$logger->log('Using mcrypt for token', JLog::DEBUG);
			$seed = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
			if ($seed != false && strlen($seed) == $length) {
				$token = $seed;
			}
		}
		if (strcmp($token, '') == 0) {
			$logger->log('The php version on your server has neither openssl nor mcrypt support! Therefore we need to fall back to insecure way of producing tokens! Please consider switching to a php version with built-in openssl support, or enabling the mcrypt module (note that on windows, only php versions >= 5.3.7 come with mcrypt modules providing the required level of randomness)!', JLog::WARNING);
			$token = self::getRandToken($length);
		}
		return sha1($token);
	}
}
