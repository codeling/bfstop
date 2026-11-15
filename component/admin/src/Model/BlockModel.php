<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\DurationHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\MVC\Model\AdminModel;

class BlockModel extends AdminModel
{
	public function getForm($data = array(), $loadData = true)
	{
		$form = $this->loadForm('com_bfstop.block', 'block',
			array('control' => 'jform', 'load_data' => $loadData));
		if (empty($form))
		{
			return false;
		}
		self::addDurationOption($form);
		return $form;
	}

	/**
	 * Gives the duration of the block being edited an option of its own if
	 * the list hasn't got one. The list only names some durations, but a
	 * block can last any number of minutes: the plugin's settings offer a
	 * week and 30 days, and the progressive block duration multiplies the
	 * duration with each repeat offense. Without an option for its value,
	 * the browser shows the first one - unlimited - and saving the block,
	 * even unchanged, made it permanent.
	 */
	public static function addDurationOption(Form $form)
	{
		$value = $form->getValue('duration');
		if (!is_numeric($value) || (int) $value < 0)
		{
			return;
		}
		$value = (string) (int) $value;
		$fields = $form->getXml()->xpath('//field[@name="duration"]');
		if (empty($fields))
		{
			return;
		}
		foreach ($fields[0]->option as $option)
		{
			if ((string) $option['value'] === $value)
			{
				return;
			}
		}
		$option = $fields[0]->addChild('option',
			htmlspecialchars(DurationHelper::toReadable($value), ENT_QUOTES | ENT_XML1, 'UTF-8'));
		$option->addAttribute('value', $value);
	}

	protected function loadFormData()
	{
		$data = Factory::getApplication()->getUserState('com_bfstop.edit.block.data', array());
		if (empty($data))
		{
			$data = $this->getItem();
		}
		return $data;
	}
}
