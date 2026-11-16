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
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Codeling\Plugin\System\Bfstop\Repository\Repositories;
use Joomla\CMS\Factory;
use Joomla\CMS\Form\Form;
use Joomla\CMS\Language\Text;
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

	public function save($data)
	{
		$id = (int) ($data['id'] ?? 0);
		$former = null;
		$table = $this->getTable();
		if ($id > 0 && $table->load($id))
		{
			$former = (string) $table->ipaddress;
		}
		if (!parent::save($data))
		{
			return false;
		}
		$this->blockThroughHtaccess((int) $this->getState($this->getName().'.id'), $former);
		return true;
	}

	/**
	 * With blocking through .htaccess, a block of the list goes into the
	 * file as well, like those of the plugin (see Bfstop::blockLocked()) -
	 * unless the web server mustn't refuse its addresses: a network with
	 * allowed addresses in it (the web server knows nothing of the allow
	 * list) or a trusted proxy (every request coming through it would be
	 * turned away). Those are only blocked in the database, which Joomla
	 * goes by. An edited block may have had another address ($former), or
	 * a duration which is over now: what no active block is left for comes
	 * out.
	 */
	private function blockThroughHtaccess($id, $former = null)
	{
		if ($id < 1 || ParamHelper::get('blockMode', 'full') !== 'htaccess')
		{
			return;
		}
		$table = $this->getTable();
		if (!$table->load($id))
		{
			return;
		}
		$address = (string) $table->ipaddress;
		$logger = LogHelper::getLogger();
		$repositories = new Repositories($logger);
		$htaccess = new HtaccessHelper(UnblockHelper::getHtaccessPath(), $logger);
		$htaccess->removeLiftedBlocks($repositories->blocks());
		if ($former !== null && $former !== $address && !in_array($former, $repositories->blocks()->allAddresses() ?? array($former), true))
		{
			// no block of the former address left at all: removeLiftedBlocks()
			// only knows addresses which have one
			$htaccess->removeAddresses(array($former), 'its block was changed');
		}
		// the block list holds a network by its network address
		if (!in_array($id, ($repositories->blocks()->activeIdsFor(explode('/', $address)[0]) ?? array()), true))
		{
			return;
		}
		$app = Factory::getApplication();
		$allowed = $repositories->allowList()->entriesOverlapping($address);
		if ($allowed === null || count($allowed) > 0)
		{
			$app->enqueueMessage(Text::_('COM_BFSTOP_IPADDRESS_ALLOWED'), 'warning');
			return;
		}
		if (IpHelper::overlapsTrustedProxy($address, IpHelper::trustedProxies()))
		{
			$app->enqueueMessage(Text::_('COM_BFSTOP_IPADDRESS_TRUSTED_PROXY'), 'warning');
			return;
		}
		if (!$htaccess->denyIP($address))
		{
			$app->enqueueMessage(Text::sprintf('COM_BFSTOP_BLOCK_HTACCESS_NOT_WRITTEN',
				htmlspecialchars($htaccess->getFileName(), ENT_QUOTES, 'UTF-8')), 'warning');
		}
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
			// a new block starts today, by the clock the plugin uses: the
			// field's "now" would be the day in UTC, see BlockTable::startTime()
			if (is_object($data) && empty($data->id) && empty($data->crdate))
			{
				$data->crdate = date('Y-m-d');
			}
		}
		return $data;
	}
}
