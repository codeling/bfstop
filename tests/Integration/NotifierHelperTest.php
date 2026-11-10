<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Codeling\Plugin\System\Bfstop\Helper\NotifierHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Uri\Uri;

/**
 * The mails are prepared in the request of a failed login. Without the site's
 * $live_site, Joomla builds every address from the host that request names,
 * which whoever sends it picks: then they must not carry the site's address.
 */
class NotifierHelperTest extends IntegrationTestCase
{
	private function withLiveSite($liveSite, callable $test)
	{
		$app = Factory::getApplication();
		$original = $app->get('live_site', '');
		$app->set('live_site', $liveSite);
		try
		{
			return $test();
		}
		finally
		{
			$app->set('live_site', $original);
		}
	}

	private function mails()
	{
		Factory::getApplication()->getLanguage()->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$notifier = new NotifierHelper($this->logger, new DatabaseHelper($this->logger), '', -1, -1, false);
		$entry = (object) array('ipaddress' => '203.0.113.5', 'username' => 'Admin', 'logtime' => date('Y-m-d H:i:s'),
			'origin' => 0);
		return array(
			'failed login body' => $notifier->getFailedLoginBody($entry),
			'blocked body' => $notifier->getBlockedBody($entry, 60),
			'site address' => NotifierHelper::siteAddress(),
		);
	}

	public function testMailsNameTheSiteOnlyWithLiveSite()
	{
		$mails = $this->withLiveSite('https://www.example.org', function () { return $this->mails(); });
		foreach ($mails as $what => $text)
		{
			$this->assertStringContainsString(Uri::root(), $text, $what);
		}

		$mails = $this->withLiveSite('', function () { return $this->mails(); });
		$notSet = Text::_('PLG_SYSTEM_BFSTOP_SITE_ADDRESS_NOT_SET');
		$this->assertNotSame('PLG_SYSTEM_BFSTOP_SITE_ADDRESS_NOT_SET', $notSet, 'the language string exists');
		foreach ($mails as $what => $text)
		{
			$this->assertStringNotContainsString(Uri::root(), $text, $what);
			$this->assertStringContainsString($notSet, $text, $what);
		}
	}
}
