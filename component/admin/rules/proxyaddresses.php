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
 * The trusted proxies: addresses or networks, separated as
 * IpHelper::parseTrustedProxies() splits them. Whatever else was typed would
 * be dropped silently by the plugin, which then takes the forwarding header
 * from none - or from more than intended. A network wider than /8 (IPv4) or
 * /16 (IPv6) is refused, like on the block and allow lists: whoever can send
 * a request from it could name any client address in the header. (CDNs
 * publish ranges of /12 or /29 at most.)
 */
class JFormRuleProxyaddresses extends FormRule
{
	public function test(SimpleXMLElement $element, $value, $group = null, ?Registry $input = null, ?Form $form = null)
	{
		foreach (IpHelper::parseTrustedProxies((string) $value) as $entry)
		{
			$valid = IpHelper::isValidIpOrSubnet($entry);
			if ($valid && strpos($entry, '/') !== false)
			{
				list($address, $bits) = explode('/', $entry);
				$valid = (int) $bits >= (strpos($address, ':') !== false
					? IpValidateHelper::MinPrefixIPv6 : IpValidateHelper::MinPrefixIPv4);
			}
			if (!$valid)
			{
				return new UnexpectedValueException(Text::sprintf('COM_BFSTOP_SETTINGS_PROXY_INVALID',
					htmlspecialchars($entry, ENT_QUOTES, 'UTF-8'), IpValidateHelper::MinPrefixIPv4, IpValidateHelper::MinPrefixIPv6));
			}
		}
		return true;
	}
}
