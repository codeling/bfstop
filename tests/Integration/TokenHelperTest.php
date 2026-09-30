<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\TokenHelper;

// (only needs Joomla's Log class, but that requires a Joomla installation)
class TokenHelperTest extends IntegrationTestCase
{
	public function testToken()
	{
		$token = TokenHelper::getToken($this->logger);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $token);
		$this->assertNotSame($token, TokenHelper::getToken($this->logger));
	}
}
