<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Rule;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Form\FormRule;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;

/**
 * The nginx deny file (see NginxDenyFile): empty, or a file the plugin may
 * write - an absolute path of a *.conf file in a writable directory, which
 * either doesn't exist yet or was written by BFStop. The plugin overwrites
 * it: any other file there would be lost.
 */
class NginxdenyfileRule extends FormRule
{
	public function test(\SimpleXMLElement $element, $value, $group = null, ?Registry $input = null, ?Form $form = null)
	{
		$value = trim((string) $value);
		if ($value === '')
		{
			return true;
		}
		$problem = NginxDenyFile::problem($value);
		if ($problem === null)
		{
			return true;
		}
		return new \UnexpectedValueException(Text::sprintf('COM_BFSTOP_SETTINGS_NGINX_DENY_FILE_'.strtoupper($problem),
			htmlspecialchars($value, ENT_QUOTES, 'UTF-8'), NginxDenyFile::Suffix));
	}
}
