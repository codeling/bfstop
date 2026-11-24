<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// For RequestClassifierTest: reads a JSON list of requests (query strings)
// from stdin, and prints for each, as JSON, what RequestClassifier says of it
// and what the Joomla site under test does with it. The first argument is the
// application and user: "site" (a guest), "admin" (a guest of the backend) or
// "admin=USERNAME".
//
// What Joomla does is found out by its own code, as far as it decides which
// component, controller and task run: AdministratorApplication::findOption()
// in the backend, ComponentHelper::isEnabled() as renderComponent() checks it,
// the dispatcher the component has (com_login's, for instance, only takes some
// tasks) and BaseController::execute() with the tasks of the controller the
// request goes to. Nothing runs, though: the dispatcher gets a factory which
// hands out a controller that only records the method execute() picks.

use Codeling\Plugin\System\Bfstop\Service\RequestClassifier;
use Joomla\CMS\Application\AdministratorApplication;
use Joomla\CMS\Application\CMSApplicationInterface;
use Joomla\CMS\Component\ComponentHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Controller\BaseController;
use Joomla\CMS\MVC\Factory\MVCFactoryInterface;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Input\Input;

require dirname(__DIR__, 2).'/bootstrap.php';

/** What ran: the controller, the task execute() was given and the method it picked. */
final class Ran
{
	public static $controller = null;
	public static $task = null;
	public static $method = null;
}

/**
 * Takes the tasks of the controller Joomla would create (its own, and those
 * it registers in its constructor) and records the method which execute()
 * picks instead of running it.
 */
final class RecordingController extends BaseController
{
	public function __construct(BaseController $real, $app, $input)
	{
		parent::__construct(array('base_path' => JPATH_BASE), null, $app, $input);
		$this->taskMap = (function () { return $this->taskMap; })->call($real);
	}

	public function execute($task)
	{
		Ran::$task = $task;
		return parent::execute($task);
	}

	// the one task method BaseController has itself, see its constructor
	public function display($cachable = false, $urlparams = false)
	{
		Ran::$method = 'display';
		return $this;
	}

	public function __call($name, $arguments)
	{
		Ran::$method = $name;
	}

	public function redirect()
	{
		return false;
	}
}

final class RecordingFactory implements MVCFactoryInterface
{
	private MVCFactoryInterface $real;

	public function __construct(MVCFactoryInterface $real)
	{
		$this->real = $real;
	}

	public function createController($name, $prefix, array $config, CMSApplicationInterface $app, Input $input)
	{
		Ran::$controller = strtolower((string) $name);
		// without it, a controller takes its directory from JPATH_COMPONENT,
		// which renderComponent() defines - once per request, so not here
		$config += array('base_path' => JPATH_BASE.'/components/'.$config['option']);
		$real = $this->real->createController($name, $prefix, $config, $app, $input);
		return $real ? new RecordingController($real, $app, $input) : null;
	}

	public function createModel($name, $prefix = '', array $config = array())
	{
		return $this->real->createModel($name, $prefix, $config);
	}

	public function createView($name, $prefix = '', $type = '', array $config = array())
	{
		return $this->real->createView($name, $prefix, $type, $config);
	}

	public function createTable($name, $prefix = '', array $config = array())
	{
		return $this->real->createTable($name, $prefix, $config);
	}
}

$client = $argv[1] ?? 'site';
if (strncmp($client, 'admin', 5) === 0)
{
	$container = Factory::getContainer();
	$container->alias('session.web.administrator', 'session.cli');
	$app = $container->get(AdministratorApplication::class);
	Factory::$application = $app;
	$app->createExtensionNamespaceMap();
	$app->loadLanguage();
	$username = (string) substr($client, 6);
	$app->loadIdentity($username === '' ? null
		: $container->get(UserFactoryInterface::class)->loadUserByUsername($username));
}
$app = Factory::getApplication();
if ($app->getIdentity() === null)
{
	// a guest, as a request without a session has
	$app->loadIdentity(null);
}
$setInput = function (Input $input)
{
	$this->input = $input;
};
// the components whose dispatchers are run; others (com_ajax, for one, is a
// legacy component: its "dispatcher" runs it) are only looked up
$dispatched = array('com_users', 'com_login', 'com_bfstop');

$results = array();
foreach (json_decode(stream_get_contents(STDIN), true) as $query)
{
	parse_str($query, $params);
	$setInput->call($app, new Input($params));
	$classifier = new RequestClassifier($app);
	$result = array(
		'query' => $query,
		'option' => $classifier->requestedOption(),
		'task' => $classifier->requestedTask(),
		'login' => $classifier->isLoginAttempt(),
		'secondFactor' => $classifier->isSecondFactorAttempt(),
		'recovery' => $classifier->passwordRecovery(),
		'unblock' => $classifier->unblockPageToken() !== null,
	);
	Ran::$controller = Ran::$task = Ran::$method = null;
	$joomla = array('option' => null, 'enabled' => false, 'controller' => null, 'task' => null, 'method' => null,
		'view' => null, 'error' => null);
	try
	{
		$joomla['option'] = $app->isClient('administrator')
			? (new ReflectionMethod($app, 'findOption'))->invoke((new ReflectionMethod($app, 'findOption'))->isStatic() ? null : $app)
			: $app->getInput()->getCmd('option', null);
		$joomla['enabled'] = $joomla['option'] !== null && ComponentHelper::isEnabled($joomla['option']);
		if ($joomla['enabled'] && in_array($joomla['option'], $dispatched, true))
		{
			$dispatcher = $app->bootComponent($joomla['option'])->getDispatcher($app);
			$factory = new ReflectionProperty($dispatcher, 'mvcFactory');
			$factory->setValue($dispatcher, new RecordingFactory($factory->getValue($dispatcher)));
			$dispatcher->dispatch();
		}
	}
	catch (Throwable $e)
	{
		// Joomla runs nothing (an error page)
		$joomla['error'] = get_class($e).': '.$e->getMessage();
	}
	$joomla['controller'] = Ran::$controller;
	$joomla['task'] = Ran::$task === null ? null : strtolower((string) Ran::$task);
	$joomla['method'] = Ran::$method === null ? null : strtolower(Ran::$method);
	$joomla['view'] = $app->getInput()->get('view', null);
	$result['joomla'] = $joomla;
	$results[] = $result;
}
echo json_encode($results, JSON_PRETTY_PRINT), "\n";
