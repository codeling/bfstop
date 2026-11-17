<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

use Codeling\Plugin\System\Bfstop\Service\RequestClassifier;

/**
 * RequestClassifier against the Joomla version under test: it works out what
 * Joomla will run for a request the way Joomla's code does (see the class),
 * and if a Joomla version does it differently, a request it doesn't
 * recognise gets past the block. CI runs this on every Joomla version of the
 * matrix (tests/ci/matrix.json), so such a change fails here.
 *
 * For many requests - each combination of the parameters below -
 * fixtures/classify.php tells what the classifier says and what Joomla's
 * code would run: the component, the controller and the method of it.
 * Recognising more than Joomla runs is allowed (it only blocks a request
 * which wouldn't do anything); the other way round is what these tests catch.
 */
class RequestClassifierTest extends IntegrationTestCase
{
	// a user who may not log in to the backend
	private const RegisteredUser = 'bfstop-classifier-registered';

	private const Options = array('', 'com_users', 'COM_Users', 'com_login', 'com_bfstop', 'com_content', 'com_ajax',
		'com_cpanel');
	private const Tasks = array(null, '', 'display', 'login', 'LOGIN', 'logout', 'user.login', 'User.Login',
		'user.LOGIN', 'user.login.x', '.login', 'user.', 'display.login', 'user.logout', 'reset.request',
		'Reset.Request', 'reset.confirm', 'reset.complete', 'remind.remind', 'user.remind', 'profile.remind',
		'registration.register', 'request', 'remind', array('user.login'));
	private const Controllers = array(null, 'user', 'User', 'reset', 'remind', 'display');
	private const Views = array(null, 'reset', 'remind', 'login', 'tokenunblock', 'Reset');

	private static $results = array();
	private $createdUsers = array();

	protected function tearDown(): void
	{
		foreach ($this->createdUsers as $id)
		{
			$this->db->setQuery('DELETE FROM #__user_usergroup_map WHERE user_id='.(int) $id);
			$this->db->execute();
			$this->db->setQuery('DELETE FROM #__users WHERE id='.(int) $id);
			$this->db->execute();
		}
	}

	/** Each combination of the parameters, as a query string. */
	private static function queries()
	{
		$queries = array();
		foreach (self::Options as $option)
		{
			foreach (self::Tasks as $task)
			{
				foreach (self::Controllers as $controller)
				{
					foreach (self::Views as $view)
					{
						$params = array_filter(array('option' => $option, 'task' => $task,
							'controller' => $controller, 'view' => $view), function ($value)
						{
							return $value !== null;
						});
						if (isset($params['view']) && $params['view'] === 'tokenunblock')
						{
							$params['token'] = 'x';
						}
						$queries[] = http_build_query($params);
					}
				}
			}
		}
		return array_values(array_unique($queries));
	}

	/**
	 * What fixtures/classify.php says of every query for $client: "site", or
	 * "admin" (by a guest) or "admin=USERNAME".
	 */
	private function classify($client)
	{
		if (!isset(self::$results[$client]))
		{
			$process = proc_open(array(PHP_BINARY, __DIR__.'/fixtures/classify.php', $client),
				array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
			fwrite($pipes[0], json_encode(self::queries()));
			fclose($pipes[0]);
			$output = stream_get_contents($pipes[1]);
			$errors = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$this->assertSame(0, proc_close($process), $output.$errors);
			$results = json_decode($output, true);
			$this->assertIsArray($results, $output.$errors);
			$this->assertCount(count(self::queries()), $results);
			self::$results[$client] = $results;
		}
		return self::$results[$client];
	}

	private function createRegisteredUser()
	{
		$id = $this->insert('#__users', array('name' => self::RegisteredUser, 'username' => self::RegisteredUser,
			'email' => self::RegisteredUser.'@example.org', 'password' => '', 'registerDate' => self::minutesAgo(0),
			'params' => '{}'), 'id');
		$this->createdUsers[] = $id;
		// Registered
		$this->insert('#__user_usergroup_map', array('user_id' => $id, 'group_id' => 2));
	}

	public static function clients()
	{
		return array(
			'site' => array('site'),
			'backend, guest' => array('admin'),
			'backend, Super User' => array('admin=Admin'),
			'backend, user without backend login' => array('admin='.self::RegisteredUser),
		);
	}

	private function results($client)
	{
		if ($client === 'admin='.self::RegisteredUser && !isset(self::$results[$client]))
		{
			$this->createRegisteredUser();
		}
		return $this->classify($client);
	}

	private static function describe(array $result)
	{
		return "'".$result['query']."': classifier ".json_encode(array_diff_key($result, array('joomla' => 1))).
			', Joomla '.json_encode($result['joomla']);
	}

	/**
	 * The component is the one Joomla runs: in the backend the one
	 * AdministratorApplication::findOption() picks, on the site the "option"
	 * parameter (in another case than the component's, Joomla finds none).
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('clients')]
	public function testComponentIsTheOneJoomlaRuns($client)
	{
		foreach ($this->results($client) as $result)
		{
			$joomla = $result['joomla'];
			if (strncmp($client, 'admin', 5) === 0)
			{
				$this->assertSame($joomla['option'], $result['option'], self::describe($result));
			}
			elseif ($joomla['enabled'])
			{
				$this->assertSame(strtolower($joomla['option']), $result['option'], self::describe($result));
			}
		}
	}

	/**
	 * The controller and task are those Joomla's dispatcher hands on, where
	 * it is ComponentDispatcher's (com_users has no dispatch() of its own).
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('clients')]
	public function testTaskIsTheOneJoomlaRuns($client)
	{
		$compared = 0;
		foreach ($this->results($client) as $result)
		{
			$joomla = $result['joomla'];
			if ($joomla['option'] !== 'com_users' || $joomla['task'] === null)
			{
				continue;
			}
			list($controller, $method) = $result['task'];
			$this->assertSame($joomla['controller'], $controller, self::describe($result));
			// no task: the dispatcher hands on "display" if there is no task
			// parameter, else what it is (''); either runs the default task
			$this->assertContains($joomla['task'], $method === '' ? array('', 'display') : array($method),
				self::describe($result));
			++$compared;
		}
		if ($client === 'site' || $client === 'admin=Admin')
		{
			$this->assertGreaterThan(100, $compared, 'requests which com_users runs a task for');
		}
	}

	/**
	 * Every request for which Joomla runs the login of com_users or com_login
	 * is recognised as a login attempt (which "Login only" blocks).
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('clients')]
	public function testEveryLoginJoomlaRunsIsRecognised($client)
	{
		$logins = 0;
		foreach ($this->results($client) as $result)
		{
			$joomla = $result['joomla'];
			if (in_array($joomla['option'], array('com_users', 'com_login'), true) && $joomla['method'] === 'login')
			{
				$this->assertTrue($result['login'], self::describe($result));
				++$logins;
			}
		}
		// the backend logs in a guest's requests of com_login only; a user
		// who is logged in already has no login task in com_users there
		if ($client !== 'admin=Admin')
		{
			$this->assertGreaterThan(10, $logins, 'requests which run a login');
		}
	}

	/**
	 * A request let through to the password recovery runs nothing else: the
	 * reset or remind view, or one of the tasks of their forms.
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('clients')]
	public function testPasswordRecoveryRunsNothingElse($client)
	{
		$passed = 0;
		foreach ($this->results($client) as $result)
		{
			$joomla = $result['joomla'];
			if ($result['recovery'] === null || $joomla['method'] === null)
			{
				// not let through, or Joomla runs nothing for it
				continue;
			}
			$this->assertSame('site', $client, self::describe($result));
			$this->assertSame('com_users', $joomla['option'], self::describe($result));
			if ($joomla['method'] === 'display')
			{
				// the view's class is found by ucfirst() of its name
				$this->assertContains(strtolower((string) $joomla['view']), array('reset', 'remind'), self::describe($result));
			}
			else
			{
				$this->assertContains($joomla['controller'].'.'.$joomla['method'],
					RequestClassifier::PasswordRecoveryTasks, self::describe($result));
			}
			++$passed;
		}
		if ($client === 'site')
		{
			$this->assertGreaterThan(10, $passed, 'requests let through to the password recovery');
		}
	}

	/** A request let through to the unblock page runs nothing else. */
	#[\PHPUnit\Framework\Attributes\DataProvider('clients')]
	public function testUnblockPageRunsNothingElse($client)
	{
		$passed = 0;
		foreach ($this->results($client) as $result)
		{
			$joomla = $result['joomla'];
			if (!$result['unblock'] || $joomla['method'] === null)
			{
				continue;
			}
			$this->assertSame('site', $client, self::describe($result));
			$this->assertSame(array('com_bfstop', 'display', 'display', 'tokenunblock'),
				array($joomla['option'], $joomla['controller'], $joomla['method'], $joomla['view']),
				self::describe($result));
			++$passed;
		}
		if ($client === 'site')
		{
			$this->assertGreaterThan(0, $passed, 'requests let through to the unblock page');
		}
	}
}
