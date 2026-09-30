<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Component\Bfstop\Administrator\Controller\DisplayController;
use Codeling\Component\Bfstop\Administrator\Model\AllowModel;
use Codeling\Component\Bfstop\Administrator\Model\AllowlistModel;
use Codeling\Component\Bfstop\Administrator\Model\BlockModel;
use Codeling\Component\Bfstop\Administrator\Model\BlocklistModel;
use Codeling\Component\Bfstop\Administrator\Model\FailedloginlistModel;
use Codeling\Component\Bfstop\Administrator\Model\UsernamestatsModel;
use Codeling\Component\Bfstop\Site\Model\TokenunblockModel;
use Codeling\Plugin\System\Bfstop\Helper\DatabaseHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Factory\MVCFactory;

/**
 * Database access of the component (https://github.com/codeling/com_bfstop),
 * loaded from the checkout given in COM_BFSTOP_ROOT.
 */
class ComponentTest extends IntegrationTestCase
{
	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		if (!getenv('COM_BFSTOP_ROOT'))
		{
			self::markTestSkipped('COM_BFSTOP_ROOT not set, see tests/README.md');
		}
	}

	private function model($class)
	{
		$model = new $class(array('dbo' => $this->db), new MVCFactory('Codeling\\Component\\Bfstop'));
		$model->setDatabase($this->db);
		return $model;
	}

	private function listCount($class)
	{
		$model = $this->model($class);
		$getListQuery = new \ReflectionMethod($model, 'getListQuery');
		$this->db->setQuery($getListQuery->invoke($model));
		return count($this->db->loadObjectList());
	}

	/**
	 * Saves a new entry like the component's edit views do; the id comes
	 * empty from the form when creating a new entry
	 */
	private function saveNew($modelClass, array $data)
	{
		$model = $this->model($modelClass);
		$model->getState(); // populate the state now, so it doesn't overwrite the saved id later
		$this->assertTrue($model->save(array('id' => '') + $data), implode(', ', $model->getErrors()));
		return (int) $model->getState($model->getName().'.id');
	}

	public function testTablesAndListViews()
	{
		$blockId = $this->saveNew(BlockModel::class,
			array('ipaddress' => '192.0.2.0/24', 'crdate' => '2026-01-02', 'duration' => '0'));
		$allowId = $this->saveNew(AllowModel::class,
			array('ipaddress' => '198.51.100.0/24', 'notes' => 'test'));
		$this->assertGreaterThan(0, $blockId);
		$this->assertGreaterThan(0, $allowId);
		$this->insert('#__bfstop_unblock', array('block_id' => $blockId, 'source' => 0, 'crdate' => self::minutesAgo(0)));
		$this->insert('#__bfstop_failedlogin', array('ipaddress' => '192.0.2.1', 'logtime' => self::minutesAgo(0), 'username' => 'bob', 'origin' => 0));

		$this->assertSame(1, $this->listCount(BlocklistModel::class));
		$this->assertSame(1, $this->listCount(AllowlistModel::class));
		$this->assertSame(1, $this->listCount(FailedloginlistModel::class));

		$this->model(AllowlistModel::class)->remove(array($allowId), $this->logger);
		$this->assertSame(0, $this->listCount(AllowlistModel::class));
	}

	public function testPurgeFailedLogins()
	{
		$this->insert('#__bfstop_failedlogin', array('ipaddress' => '192.0.2.1', 'logtime' => self::minutesAgo(31 * 24 * 60), 'username' => 'old', 'origin' => 0));
		$this->insert('#__bfstop_failedlogin', array('ipaddress' => '192.0.2.1', 'logtime' => self::minutesAgo(0), 'username' => 'new', 'origin' => 0));
		$this->assertSame(1, $this->model(FailedloginlistModel::class)->purgeOlderThan(30));
		$this->assertSame('new', $this->queryValue('SELECT username FROM #__bfstop_failedlogin'));
	}

	public function testUsernameStatistics()
	{
		$this->insert('#__bfstop_username_stats', array('username' => 'Admin', 'attempts' => 12,
			'first_attempt' => self::minutesAgo(3 * 24 * 60), 'last_attempt' => self::minutesAgo(60)));
		$this->insert('#__bfstop_username_stats', array('username' => 'old', 'attempts' => 3,
			'first_attempt' => self::minutesAgo(40 * 24 * 60), 'last_attempt' => self::minutesAgo(31 * 24 * 60)));

		$this->assertSame(2, $this->listCount(UsernamestatsModel::class));
		$model = $this->model(UsernamestatsModel::class);
		$this->assertSame(12, $model->getMaxAttempts());
		$this->assertSame(1, $model->purgeNotSeenFor(30));
		$this->assertSame('Admin', $this->queryValue('SELECT username FROM #__bfstop_username_stats'));
	}

	public function testUnblockViaEmailToken()
	{
		$blockId = $this->insert('#__bfstop_bannedip', array('ipaddress' => '203.0.113.5', 'crdate' => self::minutesAgo(0), 'duration' => 60), 'id');
		$this->insert('#__bfstop_unblock_token', array('token' => 'expired', 'block_id' => $blockId, 'crdate' => self::minutesAgo(4 * 24 * 60)));
		$this->insert('#__bfstop_unblock_token', array('token' => 'valid', 'block_id' => $blockId, 'crdate' => self::minutesAgo(60)));
		$helper = new DatabaseHelper($this->logger);
		$this->assertTrue($helper->isIPBlocked('203.0.113.5'));

		$model = $this->model(TokenunblockModel::class);
		$this->assertFalse((bool) $model->unblock('expired', $this->logger), 'expired token must not unblock');
		$this->logger->errors = array(); // expected: "token not found" error
		$this->assertTrue((bool) $model->unblock('valid', $this->logger));

		$this->assertFalse($helper->isIPBlocked('203.0.113.5'));
		$this->assertSame(1, (int) $this->queryValue('SELECT source FROM #__bfstop_unblock WHERE block_id='.$blockId));
		$this->assertSame(0, (int) $this->queryValue('SELECT COUNT(*) FROM #__bfstop_unblock_token'));
	}

	public function testWarnsAboutAdminUserCaseInsensitively()
	{
		// tests/ci/install-joomla.sh creates the super user as "Admin"
		$app = Factory::getApplication();
		$app->getMessageQueue(true);
		$controller = new DisplayController(array('base_path' => JPATH_ADMINISTRATOR.'/components/com_bfstop'), new MVCFactory('Codeling\\Component\\Bfstop'), $app, $app->getInput());
		$controller->warnIfAdminUserExists();
		$this->assertCount(1, $app->getMessageQueue(true));
	}
}
