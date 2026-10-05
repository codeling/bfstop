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

class JFormRuleGeodbpath extends FormRule
{
	public function test(SimpleXMLElement $element, $value, $group = null, Registry $input = null, Form $form = null)
	{
		$value = (string) $value;
		if ($value === '')
		{
			return true;
		}
		// a plain file name of a MaxMind database: no stream wrapper (phar://,
		// ftp://, ...), no control characters
		if (preg_match('/[\x00-\x1f]/', $value) || preg_match('#^[a-z][a-z0-9+.-]*://#i', $value) ||
			!preg_match('/\.mmdb\z/i', $value))
		{
			return new UnexpectedValueException(Text::_('COM_BFSTOP_SETTINGS_GEOIP_DB_PATH_INVALID'));
		}
		return true;
	}
}
