<?php
/*
 * @package BFStop Console Plugin (plg_console_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\Console\Bfstop\Command;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\HtaccessHelper;
use Codeling\Library\Bfstop\Helper\IpHelper;
use Codeling\Library\Bfstop\Helper\NginxDenyFile;
use Codeling\Library\Bfstop\Repository\BlockRepository;
use Codeling\Library\Bfstop\Settings;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * bfstop:unblock - lifts the blocks of an address, with its entries in the
 * .htaccess file and the nginx deny file: for an administrator who can't
 * reach the backend any more (a proxy got blocked, and with it everybody).
 */
class UnblockCommand extends BfstopCommand
{
	protected static $defaultName = 'bfstop:unblock';

	protected function configure(): void
	{
		$this->setDescription('Lifts the blocks of an IP address, including its .htaccess and nginx entries');
		$this->addArgument('address', InputArgument::REQUIRED, 'The IP address (or blocked network) to unblock');
		$this->setHelp("<info>%command.name% 203.0.113.5</info> lifts every active block which contains the address\n".
			"(the address itself, or a blocked network it is in), and takes the address out of the .htaccess file\n".
			"and the nginx deny file of the settings. If a proxy was blocked, set up its proxy settings next.");
	}

	protected function doExecute(InputInterface $input, OutputInterface $output): int
	{
		$io = new SymfonyStyle($input, $output);
		$address = IpHelper::canonicalEntry((string) $input->getArgument('address'));
		if ($address === null)
		{
			$io->error('Not an IP address or network: '.(string) $input->getArgument('address'));
			return 2;
		}
		$repositories = self::repositories();
		$blocks = $repositories->blocks();
		// a network stands for its first address: its own block is among those which contain that
		$ids = $blocks->activeIdsFor(explode('/', $address)[0]);
		if ($ids === null)
		{
			$io->error('The block list could not be read, see the log of Brute Force Stop.');
			return 1;
		}
		$lifted = count($ids) === 0 || $blocks->lift($ids, BlockRepository::LiftedByAdministrator);
		$settings = Settings::stored();
		$htaccess = new HtaccessHelper(HtaccessHelper::resolvePath(Settings::string($settings, 'htaccessPath')), $repositories->logger());
		// what the plugin wrote of the blocks which are over, and the address itself, also if it was added by hand
		$htaccess->removeStaleBlocks($blocks, Settings::string($settings, 'blockMode') === 'htaccess');
		$removed = $htaccess->removeAddresses(array($address), 'unblocked on the command line');
		NginxDenyFile::syncForSettings($settings, $repositories);
		if (!$lifted || $removed === false)
		{
			$io->error('Not everything could be lifted: see the log of Brute Force Stop.');
			return 1;
		}
		$io->success(count($ids) === 0 && $removed === 0
			? $address.' had no active block.'
			: 'Lifted '.count($ids).' block(s) of '.$address.($removed > 0 ? ', and took it out of '.$htaccess->getFileName() : '').'.');
		return 0;
	}
}
