<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Helper;

defined('_JEXEC') or die;

use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Factory\MVCFactoryServiceInterface;
use Joomla\Database\DatabaseInterface;
use Joomla\Database\ParameterType;

/**
 * What administrators do with BFStop, in Joomla's User Actions Log (issue
 * #285): blocks added, changed and lifted, the allow list, the .htaccess
 * entries, the settings, the purges and the clearing of BFStop's own log -
 * and the blocks lifted through the link of an unblock mail. BFStop's own
 * log can be cleared by the very people it would hold to account, and is
 * kept for four weeks by default; the User Actions Log can only be purged
 * by a super user.
 *
 * Only what people do, not what the plugin does by itself (the blocks of
 * failed logins): those are what the block list is for, and a botnet would
 * fill the User Actions Log with them.
 *
 * As for Joomla's own extensions, it is logged if "Brute Force Stop" is
 * among the extensions the User Actions Log records (its options, "Events To
 * Log"): the installation registers it there (see installscript.php).
 */
final class ActionLogHelper
{
	public const Extension = 'com_bfstop';
	// the message language keys are this followed by the action, in upper case
	public const KeyPrefix = 'COM_BFSTOP_ACTIONLOG_';

	/**
	 * Logs $action (block_added, block_changed, blocks_lifted, ...: the end of
	 * its language key) by the current user, with the placeholders $data of
	 * its message. Never fails: what can't be logged is noted in BFStop's log.
	 *
	 * @param array $data placeholder => value; values are escaped where shown
	 */
	public static function log(string $action, array $data = array()): void
	{
		try
		{
			if (!self::isEnabled())
			{
				return;
			}
			$app = Factory::getApplication();
			$user = $app->getIdentity();
			$userId = $user ? (int) $user->id : 0;
			$message = array_map(fn ($value) => is_array($value) ? implode(', ', $value) : (string) $value, $data) + array(
				'action' => $action,
				'userid' => (string) $userId,
				'username' => $user ? (string) $user->username : '',
				'accountlink' => 'index.php?option=com_users&task=user.edit&id='.$userId,
			);
			// com_actionlogs' ActionlogModel, as Joomla's own action log plugins use it
			$component = $app->bootComponent('com_actionlogs');
			if (!$component instanceof MVCFactoryServiceInterface)
			{
				return;
			}
			$model = $component->getMVCFactory()->createModel('Actionlog', 'Administrator', array('ignore_request' => true));
			if (!is_object($model) || !method_exists($model, 'addLog'))
			{
				return;
			}
			$model->addLog(array($message), self::KeyPrefix.strtoupper($action), self::Extension, $userId);
		}
		catch (\Throwable $e)
		{
			LogHelper::getLogger()->log('Could not write "'.$action.'" to the User Actions Log: '.$e->getMessage(), Log::WARNING);
		}
	}

	/**
	 * Whether the User Actions Log records BFStop: it is among the extensions
	 * of its option "Events To Log".
	 */
	public static function isEnabled(): bool
	{
		if (!ComponentHelper::isEnabled('com_actionlogs'))
		{
			return false;
		}
		$extensions = ComponentHelper::getParams('com_actionlogs')->get('loggable_extensions', array());
		return in_array(self::Extension, (array) $extensions, true);
	}

	/**
	 * The addresses of the rows $ids of the list $table (#__bfstop_bannedip,
	 * #__bfstop_allowlist), for the message about what happened to them: read
	 * before it happens, the rows may be gone afterwards.
	 *
	 * @param int[] $ids
	 * @return string[] id => address
	 */
	public static function addresses(string $table, array $ids): array
	{
		$ids = array_values(array_filter(array_map('intval', $ids)));
		if (count($ids) === 0 || !in_array($table, array('#__bfstop_bannedip', '#__bfstop_allowlist'), true))
		{
			return array();
		}
		try
		{
			$db = Factory::getContainer()->get(DatabaseInterface::class);
			$query = $db->createQuery()
				->select($db->quoteName(array('id', 'ipaddress')))
				->from($db->quoteName($table))
				->whereIn($db->quoteName('id'), $ids, ParameterType::INTEGER)
				->order($db->quoteName('id'));
			$db->setQuery($query);
			return $db->loadAssocList('id', 'ipaddress') ?: array();
		}
		catch (\Throwable $e)
		{
			return array();
		}
	}
}
