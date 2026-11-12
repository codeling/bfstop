<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Plugin\System\Bfstop\Helper\ApiHelper;
use PHPUnit\Framework\TestCase;

class ApiHelperTest extends TestCase
{
	public function testRequestWithoutCredentials()
	{
		$this->assertNull(ApiHelper::credentialsUsername(array()));
		$this->assertNull(ApiHelper::credentialsUsername(array('HTTP_AUTHORIZATION' => '', 'HTTP_X_JOOMLA_TOKEN' => ' ')));
		$this->assertNull(ApiHelper::credentialsUsername(array('PHP_AUTH_USER' => array('x'))), 'not a string');
	}

	public function testHttpBasicAuthenticationGivesTheUsername()
	{
		$this->assertSame('bob', ApiHelper::credentialsUsername(array('PHP_AUTH_USER' => 'bob', 'PHP_AUTH_PW' => 'x')));
		// a password without a username is an attempt all the same
		$this->assertSame('', ApiHelper::credentialsUsername(array('PHP_AUTH_PW' => 'x')));
		// the header as it is, if PHP didn't take it apart (CGI/FastCGI)
		$this->assertSame('carol', ApiHelper::credentialsUsername(
			array('HTTP_AUTHORIZATION' => 'Basic '.base64_encode('carol:pass:with:colons'))));
		$this->assertSame('dave', ApiHelper::credentialsUsername(
			array('REDIRECT_HTTP_AUTHORIZATION' => 'basic '.base64_encode('dave:x'))));
		$this->assertSame('erin', ApiHelper::credentialsUsername(array(), 'Basic '.base64_encode('erin:x')),
			'the header from apache_request_headers()');
		$this->assertSame('', ApiHelper::credentialsUsername(array('HTTP_AUTHORIZATION' => 'Basic !!!')), 'not base64');
	}

	public function testTokensNameNoUsername()
	{
		$this->assertSame('', ApiHelper::credentialsUsername(array('HTTP_AUTHORIZATION' => 'Bearer c2hhMjU2OjQyOmFiYw==')));
		$this->assertSame('', ApiHelper::credentialsUsername(array('HTTP_X_JOOMLA_TOKEN' => 'c2hhMjU2OjQyOmFiYw==')));
		$this->assertSame('', ApiHelper::credentialsUsername(array(), 'Bearer abc'));
	}

	public function testOnlyBasicCredentialsAreAPassword()
	{
		$this->assertTrue(ApiHelper::credentialsArePassword(array('PHP_AUTH_USER' => 'bob', 'PHP_AUTH_PW' => 'x')));
		$this->assertTrue(ApiHelper::credentialsArePassword(array('PHP_AUTH_PW' => 'x')));
		$this->assertTrue(ApiHelper::credentialsArePassword(array('PHP_AUTH_USER' => 'bob')));
		$this->assertTrue(ApiHelper::credentialsArePassword(
			array('HTTP_AUTHORIZATION' => 'Basic '.base64_encode('carol:x'))));
		$this->assertTrue(ApiHelper::credentialsArePassword(
			array('REDIRECT_HTTP_AUTHORIZATION' => 'basic '.base64_encode('dave:x'))));
		$this->assertTrue(ApiHelper::credentialsArePassword(array(), 'Basic '.base64_encode('erin:x')));
		$this->assertTrue(ApiHelper::credentialsArePassword(array('HTTP_AUTHORIZATION' => 'Basic !!!')), 'not base64');

		$this->assertFalse(ApiHelper::credentialsArePassword(array()));
		$this->assertFalse(ApiHelper::credentialsArePassword(array('HTTP_AUTHORIZATION' => 'Bearer c2hhMjU2OjQyOmFiYw==')));
		$this->assertFalse(ApiHelper::credentialsArePassword(array('HTTP_X_JOOMLA_TOKEN' => 'c2hhMjU2OjQyOmFiYw==')));
		$this->assertFalse(ApiHelper::credentialsArePassword(array(), 'Bearer abc'));
		$this->assertFalse(ApiHelper::credentialsArePassword(array('PHP_AUTH_USER' => array('x'))), 'not a string');
	}
}
