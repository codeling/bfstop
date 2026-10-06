<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Site\View\Tokenunblock;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Codeling\Component\Bfstop\Administrator\Helper\ParamHelper;
use Codeling\Component\Bfstop\Site\Model\TokenunblockModel;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\View\HtmlView as BaseHtmlView;
use Joomla\CMS\Router\Route;

class HtmlView extends BaseHtmlView
{
	function getLoginLink()
	{
		return Route::_('index.php?option=com_users&view=login');
	}

	function getPasswordResetLink()
	{
		return Route::_('index.php?option=com_users&view=reset');
	}

	function display($tpl = null)
	{
		// clear the messages still enqueued from the invalid login attempt:
		$session = Factory::getSession();
		$session->set('application.queue', null);
		$app = Factory::getApplication();
		$input = $app->input;
		$this->token = $input->getString('token', '');
		$this->showConfirmation = false;
		$logger = LogHelper::getLogger();
		$this->model = $this->getModel();
		$result = $this->model->process($this->token,
			$input->getMethod() === 'POST',
			IpHelper::getAddress($logger),
			$logger);
		switch ($result)
		{
			case TokenunblockModel::ResultConfirm:
				$this->showConfirmation = true;
				$this->message = Text::_('COM_BFSTOP_UNBLOCKTOKEN_CONFIRM');
				break;
			case TokenunblockModel::ResultUnblocked:
				$this->message = Text::sprintf('COM_BFSTOP_UNBLOCKTOKEN_SUCCESS',
					$this->getLoginLink(),
					$this->getPasswordResetLink());
				break;
			case TokenunblockModel::ResultWrongIp:
				$this->message = Text::_('COM_BFSTOP_UNBLOCKTOKEN_WRONG_IP');
				break;
			case TokenunblockModel::ResultNotFound:
			case TokenunblockModel::ResultFailed:
				$this->message = Text::_('COM_BFSTOP_UNBLOCKTOKEN_FAILED');
				break;
			default:
				$this->message = Text::_('COM_BFSTOP_UNBLOCKTOKEN_INVALID');
		}
		// The status is only set if the plugin's "Use HTTP Error" setting is
		// on: a web server or CDN replacing error pages with its own would
		// otherwise hide the message from the user.
		if ((bool) ParamHelper::get('useHttpError', 'params', true))
		{
			$status = TokenunblockModel::httpStatus($result);
			if ($status !== 200)
			{
				$app->setHeader('status', $status, true);
			}
		}
		// The link carries a secret: neither the page nor the address may be
		// kept by caches, passed on to other sites in the Referer header of
		// requests for resources the template loads from them, or indexed.
		$app->allowCache(false);
		$app->setHeader('Referrer-Policy', 'no-referrer', true);
		$app->setHeader('X-Robots-Tag', 'noindex, nofollow', true);
		parent::display($tpl);
	}
}
