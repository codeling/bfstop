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
use Joomla\Registry\Registry;

class JFormRuleDate extends FormRule
{
	public function test(SimpleXMLElement $element, $value, $group = null, Registry $input = null, Form $form = null)
	{
		if ($value === '' || $value === null)
		{
			return true;
		}
		// PHP date()-syntax format, e.g. "Y-m-d" - not the strftime-style
		// "format" attribute used by the built-in "calendar" field type.
		$format = (string) $element['dateformat'];
		if ($format === '')
		{
			$format = 'Y-m-d';
		}
		$dt = DateTime::createFromFormat($format, $value);
		// DateTime::createFromFormat() silently rolls invalid values like
		// "2024-02-30" over into a valid date, so make sure the parsed date
		// actually reproduces the input value before accepting it.
		return ($dt instanceof DateTime) && ($dt->format($format) === $value);
	}
}
