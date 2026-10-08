<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

defined('_JEXEC') or die;

use Joomla\CMS\Form\Form;
use Joomla\CMS\Form\FormRule;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;

/**
 * Email addresses separated by semicolons, as the notification setting takes
 * them; the value ends up in the recipients of mails sent by the plugin.
 */
class JFormRuleEmaillist extends FormRule
{
	public function test(SimpleXMLElement $element, $value, $group = null, Registry $input = null, Form $form = null)
	{
		$value = trim((string) $value);
		if ($value === '')
		{
			return true;
		}
		foreach (explode(';', $value) as $address)
		{
			if (filter_var(trim($address), FILTER_VALIDATE_EMAIL) === false)
			{
				return new UnexpectedValueException(Text::sprintf('COM_BFSTOP_SETTINGS_EMAIL_INVALID',
					htmlspecialchars(trim($address), ENT_QUOTES, 'UTF-8')));
			}
		}
		return true;
	}
}
