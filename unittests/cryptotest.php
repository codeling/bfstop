<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
require_once('helpers/crypto.php');

class Log {
	const DEBUG    = 128;
	const INFO     =  64;
	const NOTICE   =  32;
	const WARNING  =  16;
	const ERROR    =   8;
	const CRITICAL =   4;
	const ALERT    =   2;
	const EMERGENCY=   1;
}

class LogMsg {
	public $message;
	public $level;
}

class TestLogger {
	public $logMessages = array();
	public function log($msg, $lvl) {
		$logMsg = new LogMsg;
		$logMsg->message = $msg;
		$logMsg->level = $lvl;
		$this->logMessages[] = $logMsg;
	}
}

class BFStopTokenGeneratorTest extends PHPUnit_Framework_TestCase
{
	public function testGenerate() {
		$testlogger = new TestLogger;
		$token = BFStopTokenGenerator::getToken($testlogger);
		printf("Generated Token: %s", $token);
		$this->assertEquals(strlen($token), 40);
		$this->assertTrue(ctype_xdigit($token));

		if (function_exists('openssl_random_pseudo_bytes') ||
			(function_exists('mcrypt_create_iv') &&
			(strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ||
			version_compare(phpversion(), '5.3.7') > 0) ) ) {
			$this->assertEquals(sizeof($testlogger->logMessages), 1);
			$this->assertEquals($testlogger->logMessages[0]->level, Log::VERBOSE);
		} else {
			$this->assertEquals(sizeof($testlogger->logMessages), 1);
			$this->assertEquals($testlogger->logMessages[0]->level, Log::WARNING);
		}
	}
}
