<?php
/*
 * @package BFStop Console Plugin (plg_console_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\Console\Bfstop\Command;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Language\Text;
use Joomla\Registry\Registry;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * bfstop:setup - the required steps of the setup assistant, and "Activate
 * protection", from the command line: for sites installed or updated there,
 * and for automation. The command line has no request of the
 * administrator's browser to check the proxy settings with (the assistant's
 * dry run): it takes them as given.
 */
class SetupCommand extends BfstopCommand
{
	protected static $defaultName = 'bfstop:setup';

	protected function configure(): void
	{
		$this->setDescription('Completes the setup of Brute Force Stop and activates protection');
		$this->addOption('no-proxy', null, InputOption::VALUE_NONE,
			'Visitors reach the site directly (or the web server already resolves their address)');
		$this->addOption('trusted', null, InputOption::VALUE_REQUIRED,
			'The addresses or networks of the proxies in front of the site, separated by commas');
		$this->addOption('header', null, InputOption::VALUE_REQUIRED,
			'The header the proxy sends the visitor\'s address in, e.g. X-Forwarded-For, Forwarded or CF-Connecting-IP');
		$this->addOption('block-mode', null, InputOption::VALUE_REQUIRED,
			'The blocking mode: loginonly, full, htaccess or off (default: the current one; "off" only when given here)');
		$this->addOption('fix', null, InputOption::VALUE_NONE,
			'Replace stored values which keep the settings from being saved by the proposed ones');
		$this->setHelp("<info>%command.name% --no-proxy</info>\n".
			"<info>%command.name% --trusted=10.0.0.5,10.0.0.6 --header=X-Forwarded-For</info>\n\n".
			"Saves the proxy settings (as the setup assistant's proxy step does) and the blocking mode, and enables\n".
			"the system plugin. Wrong proxy settings block every visitor, or let attackers choose their address:\n".
			"behind a proxy, check afterwards in the backend that the settings page shows your own address\n".
			"(Settings, Proxy / Load Balancer). Keep them up to date whenever your hosting changes.");
	}

	/** The $_SERVER key of the header named $name (as written, or as the key). */
	public static function headerKey(string $name): ?string
	{
		foreach (IpHelper::KnownProxyHeaders as $key)
		{
			if (strcasecmp($key, $name) === 0 || strcasecmp(IpHelper::headerName($key), $name) === 0)
			{
				return $key;
			}
		}
		return null;
	}

	protected function doExecute(InputInterface $input, OutputInterface $output): int
	{
		$io = new SymfonyStyle($input, $output);
		$this->loadLanguage();
		$model = $this->setupModel();
		if ($model === null)
		{
			$io->error('The component of Brute Force Stop (com_bfstop) is not installed.');
			return 1;
		}
		$noProxy = (bool) $input->getOption('no-proxy');
		$trusted = (string) $input->getOption('trusted');
		$header = (string) $input->getOption('header');
		if ($noProxy === ($trusted !== ''))
		{
			$io->error('Give either --no-proxy or --trusted=<proxies> with --header=<header>.');
			return 2;
		}
		$headerKey = null;
		if (!$noProxy)
		{
			$headerKey = self::headerKey($header);
			if ($headerKey === null)
			{
				$io->error('--header has to be one of: '.implode(', ', array_map(array(IpHelper::class, 'headerName'),
					IpHelper::KnownProxyHeaders)));
				return 2;
			}
		}
		$mode = (string) $input->getOption('block-mode');
		if ($mode !== '' && !in_array($mode, array('loginonly', 'full', 'htaccess', 'off'), true))
		{
			$io->error('--block-mode has to be loginonly, full, htaccess or off.');
			return 2;
		}

		$blocking = $model->blockingValues();
		if (count($blocking) > 0)
		{
			$rows = array();
			foreach ($blocking as $entry)
			{
				$rows[] = array(self::plain($entry['label']), $entry['value'], self::plain($entry['message']),
					is_array($entry['fix']) ? implode(',', $entry['fix']) : (string) $entry['fix']);
			}
			$io->table(array('Setting', 'Stored', 'Problem', 'Proposed'), $rows);
			if (!$input->getOption('fix'))
			{
				$io->error('These stored values keep the settings from being saved. Run the command again with --fix to '.
					'replace them by the proposed ones, or change them on the settings page.');
				return 1;
			}
		}

		$ok = $noProxy
			? $model->confirmNoProxy(true)
			: $model->confirmProxy((string) $headerKey, implode("\n", IpHelper::parseTrustedProxies($trusted)), null);
		if (!$ok)
		{
			$io->error(self::errors($model));
			return 1;
		}
		$io->text('Proxy settings saved: '.($noProxy ? 'no proxy' : 'trusted '.$trusted.', header '.IpHelper::headerName((string) $headerKey)).'.');

		$current = Settings::string(new Registry($model->storedParams()), 'blockMode');
		if ($mode === '' && $current === 'off')
		{
			$io->error('The blocking mode is "Reporting Only", which blocks nobody. Give --block-mode=off to keep it, or '.
				'--block-mode=loginonly or --block-mode=full.');
			return 1;
		}
		if (!$model->confirmBlockMode($mode !== '' ? $mode : $current, null, $mode === 'off'))
		{
			$io->error(self::errors($model));
			return 1;
		}
		$io->text('Blocking mode: '.($mode !== '' ? $mode : $current).'.');

		if (!$model->activate())
		{
			$io->error(self::errors($model));
			return 1;
		}
		$io->success(self::plain(Text::_('COM_BFSTOP_SETUP_ACTIVATED').' '.Text::_('COM_BFSTOP_SETUP_REMINDER')));
		return 0;
	}
}
