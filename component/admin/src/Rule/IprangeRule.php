<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Rule;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\IpValidateHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Form\FormRule;
use Joomla\Registry\Registry;

/**
 * An entry of the allow list: an address or a network. The error is returned, for Joomla to show
 * instead of its own; a private or reserved range is no error, only noted.
 */
class IprangeRule extends FormRule
{
	public function test(\SimpleXMLElement $element, $value, $group = null, ?Registry $input = null, ?Form $form = null)
	{
		$error = IpValidateHelper::rangeError($value);
		if ($error !== null)
		{
			return new \UnexpectedValueException($error);
		}
		$note = IpValidateHelper::privateRangeNote($value);
		if ($note !== null)
		{
			Factory::getApplication()->enqueueMessage($note, 'warning');
		}
		return true;
	}
}
