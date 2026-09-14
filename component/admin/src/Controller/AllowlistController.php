<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\AdminController;
use Joomla\CMS\Router\Route;
use Joomla\Utilities\ArrayHelper;

class AllowlistController extends AdminController
{
	public function getModel($name = 'allowlist', $prefix = '', $config = [])
	{
		$model = parent::getModel($name, $prefix, array('ignore_request' => true));
		return $model;
	}

	public function remove()
	{
		// this bypasses AdminModel's standard delete() flow (and its
		// built-in core.delete check), so the check has to happen here
		if (!Factory::getApplication()->getIdentity()->authorise('core.delete', 'com_bfstop'))
		{
			$this->setRedirect(Route::_('index.php?option=com_bfstop&view=allowlist', false),
				Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return;
		}
		$logger = LogHelper::getLogger();
		$input = Factory::getApplication()->input;
		$ids = $input->post->get('cid', array(), 'array');
		ArrayHelper::toInteger($ids);
		$model = $this->getModel('allowlist');
		$message = $model->remove($ids, $logger);
		$this->setRedirect(Route::_('index.php?option=com_bfstop&view=allowlist', false),
			$message, 'notice');
	}
}
