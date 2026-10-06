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

class JFormRuleHtaccesspath extends FormRule
{
	public function test(SimpleXMLElement $element, $value, $group = null, Registry $input = null, Form $form = null)
	{
		$value = (string) $value;
		if ($value === '')
		{
			return true;
		}
		// a plain path of the file system: no stream wrapper (phar://, ftp://,
		// ...), no control characters
		$valid = !preg_match('/[\x00-\x1f]/', $value) && !preg_match('#^[a-z][a-z0-9+.-]*://#i', $value);
		// and, if the .htaccess file is what blocks, an existing directory:
		// the plugin writes the file there
		if ($valid && $input !== null && $input->get('params.blockMode') === 'htaccess')
		{
			$valid = is_dir($value);
		}
		if (!$valid)
		{
			return new UnexpectedValueException(Text::_('COM_BFSTOP_SETTINGS_HTACCESS_PATH_INVALID'));
		}
		return true;
	}
}
