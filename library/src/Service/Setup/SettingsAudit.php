<?php
/*
 * @package BFStop Library (lib_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Library\Bfstop\Service\Setup;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\NotifierHelper;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;

/**
 * The stored settings which the settings page would refuse to save. The
 * settings form checks all of its fields whenever anything is saved, so a
 * value which an earlier version stored (and didn't check), or which became
 * invalid since (no $live_site any more), keeps every change from being
 * saved - also those of the setup assistant, which saves through the same
 * model. Found by the settings form's own validation, field by field, and
 * the checks across fields of the settings model: there is no second list of
 * rules here, only the fixes to propose.
 */
final class SettingsAudit
{
	/**
	 * The stored values of $params (in the form the settings form takes
	 * them, see SettingsModel::paramsForForm()) which don't validate.
	 *
	 * @param Form  $form       the settings form (com_bfstop's forms/settings.xml)
	 * @param array $params     the stored settings
	 * @param array $crossField the errors of the checks across fields (field
	 *                          name => message, see SettingsModel::crossFieldErrors())
	 * @return array[] field name => field, label, value (as stored), message, fix
	 *                 (the value to propose instead)
	 */
	public static function blockingValues(Form $form, array $params, array $crossField = array()): array
	{
		$input = new Registry(array('params' => $params));
		$blocking = array();
		foreach ($params as $name => $value)
		{
			$field = $form->getField((string) $name, 'params');
			if ($field === false)
			{
				// not a setting (any more): saving drops it, which is no error
				continue;
			}
			$valid = $field->validate($field->filter($value, 'params', $input), 'params', $input);
			if ($valid instanceof \Throwable)
			{
				$blocking[$name] = self::entry($form, (string) $name, $value, $valid->getMessage(), $params);
			}
		}
		foreach ($crossField as $name => $message)
		{
			if (!isset($blocking[$name]))
			{
				$blocking[$name] = self::entry($form, (string) $name, $params[$name] ?? Settings::Defaults[$name] ?? '',
					(string) $message, $params);
			}
		}
		return $blocking;
	}

	private static function entry(Form $form, string $name, $value, string $message, array $params): array
	{
		$field = $form->getField($name, 'params');
		$label = $field !== false ? Text::_((string) $field->getAttribute('label')) : $name;
		return array(
			'field' => $name,
			'label' => $label,
			'value' => is_array($value) ? implode(', ', array_map('strval', $value)) : (string) $value,
			'message' => $message,
			'fix' => self::proposedFix($name, $value, $params),
		);
	}

	/**
	 * What to propose instead of the value $value of the setting $name, with
	 * the settings $params: what can be kept of it (the valid addresses of a
	 * list), else what the setting takes without question.
	 */
	public static function proposedFix(string $name, $value, array $params)
	{
		switch ($name)
		{
			case 'emailaddress':
				// a comma or a stray ";" (which 1.x took) is the usual problem
				return implode(';', NotifierHelper::validAddresses(preg_split('/[;,\s]+/', (string) $value) ?: array()));
			case 'blockMode':
				// .htaccess on nginx, which never reads the file
				return 'full';
			case 'notifyBlockedUser':
				// unblock links without $live_site
				return '0';
			case 'riskMinBlockNumber':
				// the floor of the risk scoring may not be above the threshold
				return (string) min((int) $value, (int) ($params['blockNumber'] ?? Settings::Defaults['blockNumber']));
		}
		return (string) (Settings::Defaults[$name] ?? '');
	}
}
