<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ActionLogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\BlockPolicy;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Access\Rules;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Model\AdminModel;
use Joomla\CMS\Table\Asset;
use Joomla\CMS\Table\Extension;
use Joomla\Registry\Registry;

/**
 * The settings of BFStop, which are the params of the component's row of
 * Joomla's extensions table (see the library's Settings), and the
 * permissions of the component.
 */
class SettingsModel extends AdminModel
{
	// the settings are the component's row of Joomla's extensions table
	public function getTable($name = '', $prefix = '', $options = array())
	{
		return new Extension($this->getDatabase());
	}

	public function getForm($data = array(), $loadData = true)
	{
		$form = $this->loadForm('com_bfstop.settings', 'settings',
			array('control' => 'jform', 'load_data' => $loadData));
		if (empty($form))
		{
			return false;
		}
		return $form;
	}

	public function getItem($pk = null)
	{
		return parent::getItem($this->resolveExtensionId());
	}

	// AdminModel's own loadFormData() default (via FormBehaviorTrait) always
	// returns an empty array, so without this override the settings form
	// would bind against nothing and every field would show its XML default
	// instead of the value actually stored on the component's #__extensions row.
	protected function loadFormData()
	{
		$data = Factory::getApplication()->getUserState('com_bfstop.edit.settings.data', array());
		if (empty($data))
		{
			$data = $this->getItem();
			if (is_object($data) && isset($data->params) && is_array($data->params))
			{
				$data->params = self::paramsForForm($data->params);
			}
		}
		return $data;
	}

	/**
	 * The stored params as the form shows them: "enabledForOrigin" is a
	 * bitmask (what the plugin reads, and what 1.x stored), the form has a
	 * checkbox for each of its bits.
	 */
	public static function paramsForForm(array $params)
	{
		$params['enabledForOrigin'] = Origin::list(
			$params['enabledForOrigin'] ?? Settings::Defaults['enabledForOrigin']);
		return $params;
	}

	/**
	 * The form's params as they are stored, see paramsForForm(). The form
	 * requires a part to be ticked; should a request come without any (or
	 * only with values which are none), the setting is left out, which makes
	 * the plugin use its default - active for all parts, not for none.
	 */
	public static function paramsForStorage(array $params)
	{
		if (array_key_exists('enabledForOrigin', $params))
		{
			$mask = Origin::mask($params['enabledForOrigin']);
			if ($mask === 0)
			{
				unset($params['enabledForOrigin']);
			}
			else
			{
				$params['enabledForOrigin'] = $mask;
			}
		}
		return $params;
	}

	/**
	 * Unblock links are only safe with the site's $live_site, see
	 * BlockPolicy::effectiveNotifyBlockedUser(): without it, the settings page
	 * doesn't take them (for any IP address or only known ones).
	 */
	public function validate($form, $data, $group = null)
	{
		$valid = parent::validate($form, $data, $group);
		if (is_array($valid) && !BlockPolicy::hasLiveSite() &&
			(int) ($valid['params']['notifyBlockedUser'] ?? 0) !== 0)
		{
			$this->setError(Text::_('COM_BFSTOP_SETTINGS_NOTIFY_ANY_NEEDS_LIVE_SITE'));
			return false;
		}
		if (is_array($valid) && ($valid['params']['blockMode'] ?? '') === 'htaccess' &&
			HtaccessHelper::webServer($_SERVER['SERVER_SOFTWARE'] ?? '') === HtaccessHelper::ServerNginx)
		{
			// nginx never reads the file: the mode would only pretend to block
			// in the web server
			$this->setError(Text::sprintf('COM_BFSTOP_SETTINGS_HTACCESS_NEEDS_APACHE',
				Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_HTACCESS'), Text::_('COM_BFSTOP_SETTINGS_BLOCK_MODE_FULL')));
			return false;
		}
		if (is_array($valid))
		{
			// the floor of the risk scoring is a floor of the threshold for
			// every client (see BlockPolicy::effectiveBlockNumber()): above the
			// threshold it would raise it for everybody
			$params = new Registry($valid['params'] ?? array());
			$blockNumber = Settings::int($params, 'blockNumber');
			$minBlockNumber = Settings::int($params, 'riskMinBlockNumber');
			if ($minBlockNumber > $blockNumber)
			{
				// the label of the threshold is the plugin's, see the view
				$language = Factory::getApplication()->getLanguage();
				$language->load('plg_system_bfstop.sys', JPATH_ADMINISTRATOR)
					|| $language->load('plg_system_bfstop.sys', JPATH_PLUGINS.'/system/bfstop');
				$this->setError(Text::sprintf('COM_BFSTOP_SETTINGS_RISK_MIN_BLOCK_NUMBER_ABOVE_BLOCK_NUMBER',
					Text::_('COM_BFSTOP_SETTINGS_RISK_MIN_BLOCK_NUMBER_LABEL'), $minBlockNumber,
					Text::_('PLG_SYSTEM_BFSTOP_BLOCK_NUMBER_LABEL'), $blockNumber));
				return false;
			}
		}
		return $valid;
	}

	public function save($data)
	{
		$id = $this->resolveExtensionId();
		if ($id < 1)
		{
			$this->setError(Text::_('JLIB_APPLICATION_ERROR_SAVE_FAILED'));
			return false;
		}
		if (isset($data['rules']) && !$this->saveRules($data['rules']))
		{
			return false;
		}
		unset($data['rules']);
		$data[$this->getTable()->getKeyName()] = $id;
		$stored = $this->loadStoredParams($id);
		$data['params'] = self::paramsForStorage($data['params'] ?? array());
		if (!parent::save($data))
		{
			return false;
		}
		$this->tidyFormerHtaccessFile($stored, $data['params']);
		self::syncNginxDenyFiles($stored, is_array($data['params']) ? $data['params'] : array());
		$changed = self::changedSettings($stored, is_array($data['params']) ? $data['params'] : array());
		if (count($changed) > 0)
		{
			ActionLogHelper::log('settings_changed', array('settings' => $changed));
		}
		return true;
	}

	/**
	 * Writes the nginx deny file of the settings $params from the block list
	 * (see NginxDenyFile); the one of the settings $stored, if it is another
	 * one, gets no entries: nginx would go on blocking with it.
	 */
	public static function syncNginxDenyFiles(array $stored, array $params): void
	{
		$logger = LogHelper::getLogger();
		$former = trim((string) ($stored['nginxDenyFile'] ?? ''));
		if ($former !== '' && $former !== trim((string) ($params['nginxDenyFile'] ?? '')) && is_file($former))
		{
			(new NginxDenyFile($former, $logger))->write(array());
		}
		NginxDenyFile::syncForSettings(new Registry($params), new Repositories($logger));
	}

	/**
	 * The names of the settings which differ between $before and $after (as
	 * stored), for the User Actions Log: the names only, not the values.
	 *
	 * @return string[]
	 */
	public static function changedSettings(array $before, array $after): array
	{
		$changed = array();
		foreach (array_unique(array_merge(array_keys($before), array_keys($after))) as $name)
		{
			$old = $before[$name] ?? null;
			$new = $after[$name] ?? null;
			// stored as JSON: 5 and "5" are the same setting
			if (json_encode(is_scalar($old) ? (string) $old : $old) !== json_encode(is_scalar($new) ? (string) $new : $new))
			{
				$changed[] = (string) $name;
			}
		}
		sort($changed);
		return $changed;
	}

	/**
	 * The directory of the .htaccess file of the settings $params (the
	 * default is HtaccessHelper::resolvePath()'s), without a trailing slash,
	 * so that two spellings of the same directory compare the same.
	 */
	public static function htaccessDirectory(array $params)
	{
		return HtaccessHelper::resolvePath(rtrim((string) ($params['htaccessPath'] ?? ''), '/\\'));
	}

	/**
	 * The directory of the .htaccess file which blocked with the settings
	 * $stored, if it doesn't with $params: blocking through .htaccess was
	 * switched off, or another file was chosen. Null if there is none.
	 */
	public static function formerHtaccessDirectory(array $stored, array $params)
	{
		if (($stored['blockMode'] ?? 'full') !== 'htaccess')
		{
			return null;
		}
		$former = self::htaccessDirectory($stored);
		if (($params['blockMode'] ?? 'full') !== 'htaccess')
		{
			return $former;
		}
		$current = self::htaccessDirectory($params);
		$same = (realpath($former) !== false && realpath($former) === realpath($current)) || $former === $current;
		return $same ? null : $former;
	}

	/**
	 * Takes the plugin's blocks out of the .htaccess file which doesn't block
	 * any more (see formerHtaccessDirectory()). The plugin only ever takes
	 * entries out of the file which blocks: the addresses would stay refused
	 * by the web server for good, also once their blocks are over or lifted.
	 * The blocks themselves stay in the database, which Joomla goes by; the
	 * entries added by hand stay in the file.
	 */
	private function tidyFormerHtaccessFile(array $stored, array $params)
	{
		$directory = self::formerHtaccessDirectory($stored, $params);
		if ($directory === null)
		{
			return;
		}
		$logger = LogHelper::getLogger();
		$htaccess = new HtaccessHelper($directory, $logger);
		if ($htaccess->removeStaleBlocks((new Repositories($logger))->blocks(), false) === false)
		{
			Factory::getApplication()->enqueueMessage(Text::sprintf('COM_BFSTOP_SETTINGS_HTACCESS_NOT_TIDIED',
				htmlspecialchars($htaccess->getFileName(), ENT_QUOTES, 'UTF-8')), 'warning');
		}
	}

	/**
	 * Stores the permissions of the component, as Joomla's "Options" page
	 * does it (com_config's ComponentModel::save()): only for who may change
	 * them.
	 */
	private function saveRules(array $rules)
	{
		$user = Factory::getApplication()->getIdentity();
		if (!$user || !$user->authorise('core.admin', 'com_bfstop'))
		{
			$this->setError(Text::_('JLIB_APPLICATION_ERROR_SAVE_NOT_PERMITTED'));
			return false;
		}
		$asset = new Asset($this->getDatabase());
		if (!$asset->loadByName('com_bfstop'))
		{
			$root = new Asset($this->getDatabase());
			$root->loadByName('root.1');
			$asset->name = 'com_bfstop';
			$asset->title = 'com_bfstop';
			$asset->setLocation($root->id, 'last-child');
		}
		$asset->rules = (string) new Rules($rules);
		if (!$asset->check() || !$asset->store())
		{
			$this->setError($asset->getError());
			return false;
		}
		return true;
	}

	private function loadStoredParams($id)
	{
		$table = $this->getTable();
		if (!$table->load($id))
		{
			return array();
		}
		$params = json_decode((string) $table->params, true);
		return is_array($params) ? $params : array();
	}

	// the "settings" being edited here are not stored in a table of this
	// component; they are its params, on its #__extensions row.
	protected function resolveExtensionId()
	{
		$table = $this->getTable();
		$table->load(array('type' => 'component', 'element' => Settings::Extension));
		return (int) $table->extension_id;
	}

	/**
	 * The settings are not checked out for editing. The record is a row of
	 * Joomla's extensions table, which has the columns for it: FormController
	 * would check out the extension with "Save" (until 2.0.0, the settings
	 * were the plugin's, and the Plugin Manager showed it as locked by
	 * whoever changed the settings last) - or, given another id, any other
	 * extension.
	 */
	public function checkout($pk = null)
	{
		return true;
	}

	/**
	 * Only ever the component, whatever id is given - and the plugin, which
	 * "Save" checked out until 2.0.0, when the settings were its params (the
	 * Plugin Manager showed it as locked). That they can't be (somebody else
	 * holds them) is no error of saving the settings.
	 */
	public function checkin($pks = array())
	{
		$table = $this->getTable();
		$table->load(array('type' => 'plugin', 'folder' => 'system', 'element' => 'bfstop'));
		foreach (array($this->resolveExtensionId(), (int) $table->extension_id) as $id)
		{
			if ($id > 0)
			{
				parent::checkin($id);
			}
		}
		return true;
	}

	// the default cleanCache() only clears the "com_bfstop" group, but the
	// params of the components, which the settings are read from
	// (ComponentHelper::getParams()), are cached under "_system" - without
	// this override, a saved change wouldn't take effect until that cache
	// expired on its own (com_config cleans the same group)
	protected function cleanCache($group = null)
	{
		parent::cleanCache('_system');
	}
}
