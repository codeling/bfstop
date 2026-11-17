<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Repository;

defined('_JEXEC') or die;

use Codeling\Plugin\System\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;
use Joomla\Database\DatabaseInterface;

/**
 * The repositories of a request, made when they are first asked for: what
 * the plugin, its services and the component hold to get at the database.
 */
class Repositories
{
	private DatabaseInterface $db;
	private LoggerHelper $logger;
	private array $made = array();

	/**
	 * @param DatabaseInterface|null $db the database of the site, if none is given
	 */
	public function __construct(LoggerHelper $logger, ?DatabaseInterface $db = null)
	{
		$this->logger = $logger;
		$this->db = $db ?? Factory::getContainer()->get(DatabaseInterface::class);
	}

	public function logger(): LoggerHelper
	{
		return $this->logger;
	}

	private function repository($class)
	{
		return $this->made[$class] ??= new $class($this->db, $this->logger);
	}

	public function blocks(): BlockRepository
	{
		return $this->repository(BlockRepository::class);
	}

	public function allowList(): AllowListRepository
	{
		return $this->repository(AllowListRepository::class);
	}

	public function failedLogins(): FailedLoginRepository
	{
		return $this->repository(FailedLoginRepository::class);
	}

	public function usernameStats(): UsernameStatsRepository
	{
		return $this->repository(UsernameStatsRepository::class);
	}

	public function unblockTokens(): UnblockTokenRepository
	{
		return $this->repository(UnblockTokenRepository::class);
	}

	public function knownIps(): KnownIpRepository
	{
		return $this->repository(KnownIpRepository::class);
	}

	public function dnsCache(): DnsCacheRepository
	{
		return $this->repository(DnsCacheRepository::class);
	}

	public function users(): UserRepository
	{
		return $this->repository(UserRepository::class);
	}

	public function state(): StateRepository
	{
		return $this->repository(StateRepository::class);
	}
}
