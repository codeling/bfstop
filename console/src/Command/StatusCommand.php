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
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Library\Bfstop\Settings;
use Joomla\Registry\Registry;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * bfstop:status - where the setup stands, whether the plugin is enabled, and
 * the proxy settings.
 */
class StatusCommand extends BfstopCommand
{
	protected static $defaultName = 'bfstop:status';

	protected function configure(): void
	{
		$this->setDescription('Shows the state of the setup of Brute Force Stop, whether it is active, and its proxy settings');
		$this->setHelp("<info>%command.name%</info> shows whether Brute Force Stop is active (its system plugin enabled),\n".
			"where its setup assistant stands, and the proxy settings it reads the visitor's address with.\n".
			"Exit status 0 if protection is active and the setup complete, 1 otherwise.");
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
		$setup = $model->setupState();
		$settings = new Registry($model->storedParams());
		$enabled = $model->pluginEnabled();
		$io->title('Brute Force Stop');
		$steps = array();
		foreach (SetupState::RequiredSteps as $step)
		{
			$steps[] = $step.': '.$setup->status($step);
		}
		$useProxy = Settings::bool($settings, 'useProxy');
		$io->definitionList(
			array('Plugin "System - Brute Force Stop"' => $enabled ? 'enabled' : 'disabled'),
			array('Setup' => $setup->isCompleted() ? 'completed '.gmdate('Y-m-d H:i:s', (int) $setup->completedAt()).' UTC' : 'not completed'),
			array('Mode' => $setup->mode().($setup->from() !== null ? ' (from '.$setup->from().')' : '')),
			array('Required steps' => implode(', ', $steps)),
			array('Disabled by the update' => $setup->disabledReason() ?? 'no'),
			array('Behind a proxy' => $useProxy ? 'yes' : 'no'),
			array('Header' => $useProxy ? IpHelper::headerName(Settings::string($settings, 'proxyHeaderSource')) : '-'),
			array('Trusted proxies' => $useProxy ? implode(', ', IpHelper::parseTrustedProxies(Settings::string($settings, 'proxyIpAddress'))) : '-'),
			array('Blocking mode' => Settings::string($settings, 'blockMode')),
			array('Stored values which block saving' => (string) count($model->blockingValues()))
		);
		if (!$enabled || !$setup->isCompleted())
		{
			$io->warning('Brute Force Stop is '.($enabled ? 'enabled, but its setup is not complete' : 'not active').
				'. Complete the setup in the backend (Components - Brute Force Stop - Setup assistant), or with '.
				'"php cli/joomla.php bfstop:setup --no-proxy" (or --trusted=<proxies> --header=<header>).');
			return 1;
		}
		return 0;
	}
}
