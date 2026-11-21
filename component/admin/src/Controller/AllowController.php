<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\ActionLogHelper;
use Joomla\CMS\MVC\Controller\FormController;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

class AllowController extends FormController
{
	/**
	 * An entry of the allow list exempts addresses from everything the
	 * plugin does - a wide one switches the protection off - so adding and
	 * changing entries needs core.admin as well, like changing the settings.
	 */
	private function mayChangeAllowList()
	{
		$user = $this->app->getIdentity();
		return $user && $user->authorise('core.admin', $this->option);
	}

	protected function allowAdd($data = array())
	{
		return parent::allowAdd($data) && $this->mayChangeAllowList();
	}

	protected function allowEdit($data = array(), $key = 'id')
	{
		return parent::allowEdit($data, $key) && $this->mayChangeAllowList();
	}

	/**
	 * An entry of the allow list added or changed goes into the User
	 * Actions Log: it exempts addresses from blocking.
	 */
	protected function postSaveHook(BaseDatabaseModel $model, $validData = array())
	{
		$id = (int) $model->getState($model->getName().'.id');
		$addresses = ActionLogHelper::addresses('#__bfstop_allowlist', array($id));
		ActionLogHelper::log($model->getState($model->getName().'.new') ? 'allow_added' : 'allow_changed', array(
			'id' => $id,
			'ipaddress' => $addresses[$id] ?? (string) ($validData['ipaddress'] ?? ''),
		));
	}

	public function save($key = null, $urlVar = null)
	{
		$return = parent::save($key, $urlVar);
		$this->setRedirect('index.php?option=com_bfstop&view=allowlist');
		return $return;
	}

	public function cancel($key = null)
	{
		$return = parent::cancel($key);
		$this->setRedirect('index.php?option=com_bfstop&view=allowlist');
		return $return;
	}
}
