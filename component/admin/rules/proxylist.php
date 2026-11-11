<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\IpValidateHelper;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Form\FormRule;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;

/**
 * The trusted proxies, as the plugin takes them (IpHelper::parseTrustedProxies()):
 * addresses and networks in CIDR notation. The plugin believes what a request
 * from one of them says about the address of the client, so
 *
 * - an entry which is neither is refused, not ignored: left as it is, a typing
 *   error would make the plugin take the proxy for the client of every
 *   request - and block the proxy;
 * - a network as large as the block and allow list refuse them
 *   (IpValidateHelper) is refused here too: with 0.0.0.0/0, every visitor
 *   could choose the address their failed logins are counted against.
 */
class JFormRuleProxylist extends FormRule
{
	public function test(SimpleXMLElement $element, $value, $group = null, ?Registry $input = null, ?Form $form = null)
	{
		foreach (IpHelper::parseTrustedProxies((string) $value) as $entry)
		{
			$parts = explode('/', $entry, 2);
			$minBits = str_contains($parts[0], ':') ? IpValidateHelper::MinPrefixIPv6 : IpValidateHelper::MinPrefixIPv4;
			if (!IpHelper::isValidIpOrSubnet($entry) || (count($parts) === 2 && (int) $parts[1] < $minBits))
			{
				return new UnexpectedValueException(Text::sprintf('COM_BFSTOP_SETTINGS_PROXY_IP_INVALID',
					htmlspecialchars($entry, ENT_QUOTES, 'UTF-8'),
					IpValidateHelper::MinPrefixIPv4, IpValidateHelper::MinPrefixIPv6));
			}
		}
		return true;
	}
}
