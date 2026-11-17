<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\BlockPolicy;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Model\AdminModel;
use Joomla\CMS\Table\Extension;

class SettingsModel extends AdminModel
{
	// the settings are the plugin's row of Joomla's extensions table
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
		return parent::getItem($this->resolvePluginExtensionId());
	}

	// AdminModel's own loadFormData() default (via FormBehaviorTrait) always
	// returns an empty array, so without this override the settings form
	// would bind against nothing and every field would show its XML default
	// instead of the value actually stored on the plugin's #__extensions row.
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
		return $valid;
	}

	public function save($data)
	{
		$id = $this->resolvePluginExtensionId();
		$data[$this->getTable()->getKeyName()] = $id;
		$stored = $this->loadStoredParams($id);
		$data['params'] = self::paramsForStorage($data['params'] ?? array());
		if (!parent::save($data))
		{
			return false;
		}
		$this->tidyFormerHtaccessFile($stored, $data['params']);
		return true;
	}

	/**
	 * The directory of the .htaccess file of the settings $params.
	 */
	public static function htaccessDirectory(array $params)
	{
		$path = rtrim((string) ($params['htaccessPath'] ?? ''), '/\\');
		return $path === '' ? JPATH_ROOT : $path;
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
	// component; they are the plugin's own params, on its #__extensions row.
	protected function resolvePluginExtensionId()
	{
		$table = $this->getTable();
		$table->load(array('name' => 'plg_system_bfstop'));
		return (int) $table->extension_id;
	}

	/**
	 * The settings are not checked out for editing. The record is a row of
	 * Joomla's extensions table, which has the columns for it: FormController
	 * would check out the plugin with "Save" (the Plugin Manager then shows
	 * it as locked by whoever changed the settings last) - or, given another
	 * id, any other extension.
	 */
	public function checkout($pk = null)
	{
		return true;
	}

	/**
	 * Only ever the plugin, whatever id is given: also releases it if an
	 * earlier version left it checked out. That it can't be (somebody else
	 * holds it) is no error of saving the settings.
	 */
	public function checkin($pks = array())
	{
		$id = $this->resolvePluginExtensionId();
		if ($id > 0)
		{
			parent::checkin($id);
		}
		return true;
	}

	// the default cleanCache() only clears the "com_bfstop" group, but the
	// enabled-plugins list (with params) that PluginHelper::getPlugin() reads
	// at runtime is cached under "com_plugins" - without this override, a
	// saved change here (e.g. to the proxy/load balancer settings) wouldn't
	// actually take effect until that separate cache expired on its own.
	protected function cleanCache($group = null)
	{
		parent::cleanCache('com_plugins');
	}
}
