<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Controller;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Helper\HtaccessCheckHelper;
use Codeling\Component\Bfstop\Administrator\Helper\UnblockHelper;
use Codeling\Component\Bfstop\Administrator\Model\SetupModel;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Joomla\CMS\Application\CMSApplication;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\Router\Route;

/**
 * The tasks of the setup assistant (see SetupModel): each a POST with the
 * form token, for who may change the settings (core.admin), as the settings
 * page's. They answer with a redirect to the page of the assistant they
 * belong to.
 */
class SetupController extends BaseController
{
	// what the proxy step was given to check before it is saved, see preview()
	public const ProxyUserState = 'com_bfstop.setup.proxy';

	public function getModel($name = 'setup', $prefix = '', $config = array())
	{
		return parent::getModel($name, $prefix, array('ignore_request' => true));
	}

	private function setupModel(): SetupModel
	{
		$model = $this->getModel();
		if (!$model instanceof SetupModel)
		{
			throw new \RuntimeException('The model of the setup assistant is missing');
		}
		return $model;
	}

	private static function pageUrl(string $page): string
	{
		return Route::_('index.php?option=com_bfstop&view=setup&page='.$page, false);
	}

	/**
	 * Checks the token and the permission of the request; with neither,
	 * redirects to the page $page with the reason.
	 */
	private function allowed(string $page): bool
	{
		$this->checkToken();
		$user = $this->app->getIdentity();
		if (!$user || !$user->authorise('core.admin', 'com_bfstop'))
		{
			$this->setRedirect(self::pageUrl($page), Text::_('COM_BFSTOP_NOT_AUTHORISED'), 'error');
			return false;
		}
		return true;
	}

	/** Keeps what the proxy step was given (null: forgets it), for the page, see preview(). */
	private function keepProxyInput(?array $input): void
	{
		if ($this->app instanceof CMSApplication)
		{
			$this->app->setUserState(self::ProxyUserState, $input);
		}
	}

	/** The fixes of the stored values which block saving, as the form of the page sent them. */
	private function fixes(): array
	{
		return array_map('strval', array_filter((array) $this->input->post->get('fix', array(), 'array'), 'is_scalar'));
	}

	/**
	 * Redirects with the outcome of a task of $model on the page $page: to
	 * the next page with $success's message, or back to $page with the
	 * model's errors.
	 */
	private function finish(SetupModel $model, bool $ok, string $page, string $success): void
	{
		if ($ok)
		{
			$this->setRedirect(self::pageUrl($model->nextPage($page)), $success, 'message');
			return;
		}
		$errors = array_map(fn ($error) => $error instanceof \Throwable ? $error->getMessage() : (string) $error, $model->getErrors());
		$this->setRedirect(self::pageUrl($page), implode('<br>', $errors), 'error');
	}

	/**
	 * The proxy step, saved: "there is no proxy" (choice "none"), or the
	 * proxy settings which the dry run showed to give the administrator's
	 * own address (choice "proxy").
	 */
	public function saveProxy()
	{
		if (!$this->allowed('proxy'))
		{
			return;
		}
		$model = $this->setupModel();
		$post = $this->input->post;
		$ok = $post->getCmd('choice', '') === 'proxy'
			? $model->confirmProxy($post->getString('header', ''), $post->getString('trusted', ''),
				$post->getBool('confirm', false) ? $post->getString('address', '') : null, $this->fixes(), $_SERVER)
			: $model->confirmNoProxy($post->getBool('acknowledge', false), $this->fixes(), $_SERVER);
		if ($ok)
		{
			$this->keepProxyInput(null);
		}
		$this->finish($model, $ok, 'proxy', Text::_('COM_BFSTOP_SETUP_PROXY_SAVED').' '.Text::_('COM_BFSTOP_SETUP_REMINDER'));
	}

	/**
	 * The proxy step: the settings to check with this request (the dry run),
	 * kept for the page, which shows the client address they give.
	 */
	public function preview()
	{
		if (!$this->allowed('proxy'))
		{
			return;
		}
		$header = $this->input->post->getString('header', '');
		$this->keepProxyInput(array(
			'choice' => 'proxy',
			'header' => in_array($header, IpHelper::KnownProxyHeaders, true) ? $header : '',
			'trusted' => $this->input->post->getString('trusted', ''),
			'previewed' => true,
		));
		$this->setRedirect(self::pageUrl('proxy').'#preview');
	}

	/**
	 * The proxy step: Cloudflare's address ranges as the trusted proxies, and
	 * its header. Fetched from cloudflare.com, only now that the
	 * administrator asks for them; they still have to pass the dry run.
	 */
	public function cloudflare()
	{
		if (!$this->allowed('proxy'))
		{
			return;
		}
		$ranges = SetupModel::cloudflareRanges();
		if ($ranges === null)
		{
			$this->setRedirect(self::pageUrl('proxy'), Text::_('COM_BFSTOP_SETUP_CLOUDFLARE_FAILED'), 'error');
			return;
		}
		$this->keepProxyInput(array(
			'choice' => 'proxy',
			'header' => IpHelper::CloudflareHeader,
			'trusted' => implode("\n", $ranges),
			'previewed' => true,
		));
		$this->setRedirect(self::pageUrl('proxy').'#preview', Text::sprintf('COM_BFSTOP_SETUP_CLOUDFLARE_FETCHED', count($ranges)));
	}

	/** The blocking-mode step. */
	public function saveBlockMode()
	{
		if (!$this->allowed('blockmode'))
		{
			return;
		}
		$model = $this->setupModel();
		$ok = $model->confirmBlockMode($this->input->post->getCmd('blockMode', ''),
			$this->input->post->exists('nginxDenyFile') ? $this->input->post->getString('nginxDenyFile', '') : null,
			$this->input->post->getBool('confirmOff', false), $this->fixes());
		$this->finish($model, $ok, 'blockmode', Text::_('COM_BFSTOP_SETUP_BLOCKMODE_SAVED'));
	}

	/** The blocking-mode step: whether the web server honours the .htaccess file (see HtaccessCheckHelper). */
	public function checkHtaccess()
	{
		if (!$this->allowed('blockmode'))
		{
			return;
		}
		$dir = UnblockHelper::getHtaccessPath();
		list($message, $type) = SettingsController::htaccessCheckMessage(HtaccessCheckHelper::run($dir), $dir);
		$this->setRedirect(self::pageUrl('blockmode'), $message, $type);
	}

	/** "Activate protection" */
	public function activate()
	{
		if (!$this->allowed('summary'))
		{
			return;
		}
		$model = $this->setupModel();
		// the fixes of the stored values which block saving, if the page showed any
		$ok = (count($this->fixes()) === 0 || count($model->blockingValues()) === 0 || $model->apply(null, array(), $this->fixes())) &&
			$model->activate($_SERVER);
		$this->finish($model, $ok, 'summary',
			Text::_('COM_BFSTOP_SETUP_ACTIVATED').' '.Text::_('COM_BFSTOP_SETUP_REMINDER'));
	}

	/** "This is expected": dismisses a mismatch of the proxy settings (see ProxyMismatch). */
	public function dismiss()
	{
		if (!$this->allowed('proxy'))
		{
			return;
		}
		$this->setupModel()->dismiss($this->input->post->getAlnum('fingerprint', ''));
		$this->setRedirect(self::pageUrl('proxy'), Text::_('COM_BFSTOP_SETUP_DISMISSED'));
	}

	/** The page of the step $step (SetupModel::PageSteps), the summary for any other. */
	private static function pageOf(string $step): string
	{
		$page = array_search($step, SetupModel::PageSteps, true);
		return $page === false ? 'summary' : (string) $page;
	}

	/** Skips an optional step. */
	public function skip()
	{
		$step = $this->input->post->getCmd('step', '');
		if (!$this->allowed(self::pageOf($step)))
		{
			return;
		}
		$model = $this->setupModel();
		$this->finish($model, $model->skip($step), self::pageOf($step), Text::_('COM_BFSTOP_SETUP_SKIPPED'));
	}

	/** A step which explains (rate limiting, the scheduler), read. */
	public function acknowledge()
	{
		$step = $this->input->post->getCmd('step', '');
		if (!$this->allowed(self::pageOf($step)))
		{
			return;
		}
		$model = $this->setupModel();
		$this->finish($model, $model->acknowledge($step), self::pageOf($step), Text::_('COM_BFSTOP_SETUP_STEP_SAVED'));
	}

	/** A step of settings (notifications, protected parts, privacy), saved. */
	public function saveFields()
	{
		$step = $this->input->post->getCmd('step', '');
		if (!$this->allowed(self::pageOf($step)))
		{
			return;
		}
		$form = (array) $this->input->post->get('jform', array(), 'array');
		$model = $this->setupModel();
		$this->finish($model, $model->saveFields($step, (array) ($form['params'] ?? array()), $this->fixes()),
			self::pageOf($step), Text::_('COM_BFSTOP_SETUP_STEP_SAVED'));
	}

	/** The clean-up after the proxy fix. */
	public function cleanup()
	{
		if (!$this->allowed('cleanup'))
		{
			return;
		}
		$model = $this->setupModel();
		$this->finish($model, $model->cleanup(), 'cleanup', Text::_('COM_BFSTOP_SETUP_CLEANUP_DONE'));
	}

	/** The block section of an earlier version in .htaccess, rewritten. */
	public function upgradeHtaccess()
	{
		if (!$this->allowed('htaccess'))
		{
			return;
		}
		$model = $this->setupModel();
		$this->finish($model, $model->upgradeHtaccess(), 'htaccess', Text::_('COM_BFSTOP_SETUP_HTACCESS_DONE'));
	}

	// where the hashing of old usernames goes on, see hashUsernames()
	public const HashingUserState = 'com_bfstop.setup.hashing';

	/**
	 * Hashes the plain usernames of earlier versions (see
	 * SetupModel::hashUsernames()) for a few seconds; the page shows how far
	 * it got and offers to go on, until it is done.
	 */
	public function hashUsernames()
	{
		if (!$this->allowed('privacy'))
		{
			return;
		}
		$app = $this->app;
		$progress = $app instanceof CMSApplication ? $app->getUserState(self::HashingUserState) : null;
		$progress = is_array($progress) ? $progress : array('table' => '', 'after' => '', 'hashed' => 0);
		$round = $this->setupModel()->hashUsernames((string) $progress['table'], (string) $progress['after']);
		$hashed = (int) $progress['hashed'] + $round['hashed'];
		if ($app instanceof CMSApplication)
		{
			$app->setUserState(self::HashingUserState, $round['done'] ? null
				: array('table' => $round['table'], 'after' => $round['after'], 'hashed' => $hashed));
		}
		$this->setRedirect(self::pageUrl('privacy'), Text::sprintf($round['done']
			? 'COM_BFSTOP_SETUP_HASHING_DONE' : 'COM_BFSTOP_SETUP_HASHING_PROGRESS', $hashed), 'message');
	}
}
