#!/usr/bin/env php
<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
/**
 * Compares the footprint of two versions of the bfstop plugin, with a Joomla
 * site without bfstop as the baseline for both. The sites are set up by
 * setup-sites.sh; see README.md for what is measured and how.
 *
 * Usage: php bench.php [--sites=sites.json] [--out=dir] [--requests=200]
 *   [--warmup=20] [--sizes=0,100000] [--scenarios=a,b] [--throughput=400]
 *   [--concurrency=8] [--workers=4] [--rounds=3] [--growth=2000] [--quick]
 *   [--no-trace]
 */

const PREFIX = 'jos_';
const ATTACK_ATTEMPTS = 18;
// not a loopback address which the load generators below hand out (127.20+)
const BLOCKED_IP = '127.0.0.2';

error_reporting(E_ALL);
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$GLOBALS['reqid'] = 0;

// ---------------------------------------------------------------------------
// HTTP

function curlHandle(string $url, array $o = [])
{
	$id = ++$GLOBALS['reqid'];
	$ch = curl_init($url);
	// A browser-like User-Agent: the current plugin version scores requests without one as
	// suspicious, and delays the answer to a failed login of such a request (riskDelaySecondsPerPoint)
	$headers = array_merge(['User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0'],
		$o['headers'] ?? [], ['X-Bench-Id: ' . $id]);
	curl_setopt_array($ch, [
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_FOLLOWLOCATION => false,
		CURLOPT_TIMEOUT => 300,
		CURLOPT_FRESH_CONNECT => true,
		CURLOPT_FORBID_REUSE => true,
		CURLOPT_HTTPHEADER => $headers,
	]);
	if (isset($o['ip']))
	{
		// the source address is what the plugin sees as the client's address
		curl_setopt($ch, CURLOPT_INTERFACE, $o['ip']);
	}
	if (isset($o['post']))
	{
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($o['post']));
	}
	if (isset($o['cookies']))
	{
		curl_setopt($ch, CURLOPT_COOKIEFILE, $o['cookies']);
		curl_setopt($ch, CURLOPT_COOKIEJAR, $o['cookies']);
	}
	return array($ch, $id);
}

/** @return array{id:int,status:int,body:string,ms:float} */
function http(string $url, array $o = []): array
{
	[$ch, $id] = curlHandle($url, $o);
	$body = curl_exec($ch);
	if ($body === false && empty($o['quiet']))
	{
		fwrite(STDERR, "Request to $url failed: " . curl_error($ch) . "\n");
	}
	$r = array('id' => $id, 'status' => curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
		'body' => (string) $body, 'ms' => curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
	curl_close($ch);
	return $r;
}

/**
 * Requests made concurrently, $concurrency at a time.
 * @param array[] $requests each with 'url' and the options of curlHandle()
 */
function httpConcurrent(array $requests, int $concurrency): array
{
	$mh = curl_multi_init();
	$next = 0;
	$total = count($requests);
	$done = 0;
	$active = array();
	$latencies = array();
	$statuses = array();
	$start = microtime(true);
	while ($done < $total)
	{
		while (count($active) < $concurrency && $next < $total)
		{
			[$ch] = curlHandle($requests[$next]['url'], $requests[$next]);
			curl_multi_add_handle($mh, $ch);
			$active[(int) $ch] = $ch;
			$next++;
		}
		do
		{
			$status = curl_multi_exec($mh, $running);
		}
		while ($status === CURLM_CALL_MULTI_PERFORM);
		if ($running)
		{
			curl_multi_select($mh, 0.1);
		}
		while ($info = curl_multi_info_read($mh))
		{
			$ch = $info['handle'];
			$code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
			$statuses[$code] = ($statuses[$code] ?? 0) + 1;
			$latencies[] = curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000;
			curl_multi_remove_handle($mh, $ch);
			curl_close($ch);
			unset($active[(int) $ch]);
			$done++;
		}
	}
	$elapsed = microtime(true) - $start;
	curl_multi_close($mh);
	return array('seconds' => $elapsed, 'rps' => $total / $elapsed,
		'latencies' => $latencies, 'statuses' => $statuses);
}

// ---------------------------------------------------------------------------
// statistics

function percentile(array $values, float $p): float
{
	if (!$values)
	{
		return NAN;
	}
	sort($values);
	$rank = $p / 100 * (count($values) - 1);
	$lo = (int) floor($rank);
	$hi = (int) ceil($rank);
	return $values[$lo] + ($values[$hi] - $values[$lo]) * ($rank - $lo);
}

function summarize(array $values): array
{
	return array('n' => count($values), 'median' => percentile($values, 50),
		'p95' => percentile($values, 95),
		'mean' => $values ? array_sum($values) / count($values) : NAN);
}

// ---------------------------------------------------------------------------
// database

function connect(array $cfg, string $db): mysqli
{
	return new mysqli($cfg['db']['host'], $cfg['db']['user'], $cfg['db']['pass'], $db);
}

function hasBfstop(string $name): bool
{
	return $name !== 'none';
}

/**
 * Empties the bfstop tables and fills them with $size failed logins, a tenth
 * of that many blocks (most of them expired), and the block of BLOCKED_IP.
 */
function prepareSite(mysqli $db, string $name, int $size): void
{
	if (!hasBfstop($name))
	{
		return;
	}
	$tables = $db->query("SHOW TABLES LIKE '" . PREFIX . "bfstop\\_%'")->fetch_all();
	foreach ($tables as [$t])
	{
		$db->query("TRUNCATE TABLE `$t`");
	}
	if ($size > 0)
	{
		$db->query("INSERT INTO " . PREFIX . "bfstop_failedlogin (username, ipaddress, logtime, origin, handled) " .
			"SELECT CONCAT('user', seq % 5000), " .
			"CONCAT('10.', (seq % 20000) DIV 256, '.', seq % 256, '.1'), " .
			"NOW() - INTERVAL (seq % 604800) SECOND, 0, 0 FROM seq_1_to_$size");
		$blocks = max(1, intdiv($size, 10));
		$db->query("INSERT INTO " . PREFIX . "bfstop_bannedip (ipaddress, crdate, duration) " .
			"SELECT CONCAT('172.', (seq DIV 256) % 256, '.', seq % 256, '.1'), " .
			"IF(seq % 10 = 0, NOW() - INTERVAL (seq % 600) MINUTE, NOW() - INTERVAL 30 DAY), 1440 " .
			"FROM seq_1_to_$blocks");
	}
	$db->query("INSERT INTO " . PREFIX . "bfstop_bannedip (ipaddress, crdate, duration) " .
		"VALUES ('" . BLOCKED_IP . "', NOW(), 1440)");
}

function tableStats(mysqli $db): array
{
	$stats = array();
	$tables = $db->query("SHOW TABLES LIKE '" . PREFIX . "bfstop\\_%'")->fetch_all();
	foreach ($tables as [$t])
	{
		$db->query("ANALYZE TABLE `$t`")->fetch_all();
	}
	$res = $db->query("SELECT TABLE_NAME, TABLE_ROWS, AVG_ROW_LENGTH, DATA_LENGTH, INDEX_LENGTH FROM information_schema.TABLES " .
		"WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE '" . PREFIX . "bfstop\\_%' ORDER BY TABLE_NAME");
	foreach ($res->fetch_all(MYSQLI_ASSOC) as $row)
	{
		$stats[substr($row['TABLE_NAME'], strlen(PREFIX . 'bfstop_'))] = array(
			'rows' => (int) $db->query("SELECT COUNT(*) FROM `{$row['TABLE_NAME']}`")->fetch_row()[0],
			'avg_row' => (int) $row['AVG_ROW_LENGTH'],
			'data' => (int) $row['DATA_LENGTH'], 'index' => (int) $row['INDEX_LENGTH']);
	}
	return $stats;
}

// ---------------------------------------------------------------------------
// the PHP built-in web servers hosting the sites

function startServer(array $site, int $workers, string $metricsFile): array
{
	$cmd = array('setsid', 'php',
		'-d', 'opcache.enable=1', '-d', 'opcache.validate_timestamps=0',
		'-d', 'opcache.memory_consumption=128', '-d', 'memory_limit=512M',
		'-d', 'display_errors=0', '-d', 'auto_prepend_file=' . __DIR__ . '/prepend.php',
		'-S', '127.0.0.1:' . $site['port'], '-t', $site['dir']);
	$env = array_merge(getenv(), array('BENCH_METRICS_FILE' => $metricsFile,
		'PHP_CLI_SERVER_WORKERS' => (string) $workers));
	$log = fopen($site['dir'] . '/../server.log', 'a');
	$proc = proc_open($cmd, array(0 => array('file', '/dev/null', 'r'), 1 => $log, 2 => $log),
		$pipes, $site['dir'], $env);
	if (!is_resource($proc))
	{
		throw new RuntimeException('Cannot start the web server');
	}
	$server = array('proc' => $proc, 'pid' => proc_get_status($proc)['pid']);
	for ($i = 0; $i < 100; $i++)
	{
		if (http('http://127.0.0.1:' . $site['port'] . '/', array('quiet' => true))['status'] === 200)
		{
			return $server;
		}
		usleep(200000);
	}
	stopServer($server);
	throw new RuntimeException('Web server on port ' . $site['port'] . ' does not answer, see ' . $site['dir'] . '/../server.log');
}

function stopServer(array $server): void
{
	posix_kill(-$server['pid'], SIGTERM);
	proc_terminate($server['proc']);
	proc_close($server['proc']);
}

function baseUrl(array $site): string
{
	return 'http://127.0.0.1:' . $site['port'];
}

function readMetrics(string $file): array
{
	$metrics = array();
	foreach (file($file, FILE_IGNORE_NEW_LINES) ?: array() as $line)
	{
		$m = json_decode($line, true);
		if (is_array($m) && isset($m['id']))
		{
			$metrics[$m['id']] = $m;
		}
	}
	return $metrics;
}

// ---------------------------------------------------------------------------
// scenarios

/** the login form's CSRF token name (a random-looking field set to 1) */
function fetchLoginToken(array $site, array $o, ?array &$page = null): string
{
	$page = http(baseUrl($site) . '/index.php?option=com_users&view=login', $o);
	if (!preg_match('/<input type="hidden" name="([0-9a-f]{32})" value="1"/', $page['body'], $m))
	{
		throw new RuntimeException('No login token found in the login page of ' . baseUrl($site) . ' (status ' . $page['status'] . ')');
	}
	return $m[1];
}

function loginRequest(array $site, string $token, string $username, string $ip, string $cookies): array
{
	return array('url' => baseUrl($site) . '/index.php?option=com_users&task=user.login', 'ip' => $ip,
		'cookies' => $cookies, 'post' => array('username' => $username, 'password' => 'wrong-password',
			'return' => '', 'option' => 'com_users', 'task' => 'user.login', $token => '1'));
}

function ipFor(int $second, int $i): string
{
	return '127.' . $second . '.' . (intdiv($i, 250) % 250) . '.' . ($i % 250 + 1);
}

/**
 * Each scenario: 'run' performs one step against a site ($i counts the steps;
 * $label says how to record the request(s), null = warm-up, don't record),
 * 'batch' builds $n requests for the concurrent runs, or null if the scenario
 * has no such variant.
 */
function scenarios(): array
{
	$record = function (array &$recs, ?string $label, array $r, array $extra = []) {
		if ($label !== null)
		{
			$recs[] = array_merge(array('id' => $r['id'], 'label' => $label, 'status' => $r['status'],
				'client_ms' => $r['ms'], 'page' => str_contains($r['body'], '</html>')), $extra);
		}
	};
	return array(
		'home' => array(
			'desc' => 'anonymous GET of the front page',
			'run' => function (array $site, int $i, bool $m, array &$recs, array &$st) use ($record) {
				$record($recs, $m ? 'home' : null, http(baseUrl($site) . '/'));
			},
			'batch' => fn(array $site, int $n, int $round) => array_fill(0, $n, array('url' => baseUrl($site) . '/')),
		),
		'home_blocked' => array(
			'desc' => 'GET of the front page from a blocked address (answered by bfstop; for "no bfstop" just the normal page)',
			'run' => function (array $site, int $i, bool $m, array &$recs, array &$st) use ($record) {
				$record($recs, $m ? 'home_blocked' : null, http(baseUrl($site) . '/', array('ip' => BLOCKED_IP)));
			},
			'batch' => fn(array $site, int $n, int $round) => array_fill(0, $n, array('url' => baseUrl($site) . '/', 'ip' => BLOCKED_IP)),
		),
		'admin_login' => array(
			'desc' => 'anonymous GET of the administrator login page',
			'run' => function (array $site, int $i, bool $m, array &$recs, array &$st) use ($record) {
				$record($recs, $m ? 'admin_login' : null, http(baseUrl($site) . '/administrator/index.php'));
			},
			'batch' => fn(array $site, int $n, int $round) => array_fill(0, $n, array('url' => baseUrl($site) . '/administrator/index.php')),
		),
		'login_fail' => array(
			'desc' => 'failed frontend login (unknown user name), every one from another address and with another user name',
			'run' => function (array $site, int $i, bool $m, array &$recs, array &$st) use ($record) {
				$ip = ipFor(20, $i);
				$cookies = tempnam(sys_get_temp_dir(), 'bfperf');
				$token = fetchLoginToken($site, array('ip' => $ip, 'cookies' => $cookies), $page);
				$record($recs, $m ? 'login_page' : null, $page);
				$req = loginRequest($site, $token, 'perf_user_' . $i, $ip, $cookies);
				$r = http($req['url'], $req);
				$record($recs, $m ? 'login_fail' : null, $r);
				unlink($cookies);
			},
			'batch' => function (array $site, int $n, int $round) {
				$requests = array();
				for ($i = 0; $i < $n; $i++)
				{
					$ip = ipFor(40 + $round, $i);
					$cookies = tempnam(sys_get_temp_dir(), 'bfperf');
					$token = fetchLoginToken($site, array('ip' => $ip, 'cookies' => $cookies));
					$requests[] = loginRequest($site, $token, 'perf_user_r' . $round . '_' . $i, $ip, $cookies);
				}
				return $requests;
			},
		),
		'attack' => array(
			'desc' => 'one address repeatedly failing to log in, ' . ATTACK_ATTEMPTS . ' attempts in a row: the failed attempts, the one which gets it blocked, the rejected ones afterwards',
			'run' => function (array $site, int $i, bool $m, array &$recs, array &$st) use ($record) {
				$attempt = $i % ATTACK_ATTEMPTS;
				$ip = ipFor(30, intdiv($i, ATTACK_ATTEMPTS));
				if ($attempt === 0)
				{
					$st = array('cookies' => tempnam(sys_get_temp_dir(), 'bfperf'), 'blocked' => false);
					$st['token'] = fetchLoginToken($site, array('ip' => $ip, 'cookies' => $st['cookies']));
				}
				// another user name every time: the same one over and over would trigger
				// the account-level throttle of the current version (a deliberate 5 s sleep)
				$req = loginRequest($site, $st['token'], 'perf_target_' . $i, $ip, $st['cookies']);
				$r = http($req['url'], $req);
				$label = 'attack_fail';
				if (hasBfstop($site['name']))
				{
					$res = $site['link']->query("SELECT COUNT(*) FROM " . PREFIX . "bfstop_bannedip WHERE ipaddress = '$ip'");
					$blockedNow = $res->fetch_row()[0] > 0;
					$label = $st['blocked'] ? 'attack_rejected' : ($blockedNow ? 'attack_block' : 'attack_fail');
					$st['blocked'] = $blockedNow;
				}
				$record($recs, $m ? $label : null, $r);
				if ($attempt === ATTACK_ATTEMPTS - 1)
				{
					unlink($st['cookies']);
				}
			},
			'batch' => null,
			'step' => ATTACK_ATTEMPTS,
		),
	);
}

// ---------------------------------------------------------------------------
// the measurements

/** Sequential requests, the sites taking turns so slow drifts of the machine affect all alike. */
function runSequential(array $sites, array $servers, array $scenario, int $n, int $warmup): array
{
	$step = $scenario['step'] ?? 1;
	$n = (int) (ceil($n / $step) * $step);
	$warmup = (int) (ceil($warmup / $step) * $step);
	$names = array_keys($sites);
	$recs = array_fill_keys($names, array());
	$state = array_fill_keys($names, array());
	$total = ($warmup + $n);
	for ($i = 0; $i < $total; $i++)
	{
		$shift = intdiv($i, $step) % count($names);
		foreach (array_merge(array_slice($names, $shift), array_slice($names, 0, $shift)) as $name)
		{
			$scenario['run']($sites[$name], $i, $i >= $warmup, $recs[$name], $state[$name]);
		}
	}
	$result = array();
	foreach ($names as $name)
	{
		$metrics = readMetrics($servers[$name]['metrics']);
		$byLabel = array();
		foreach ($recs[$name] as $rec)
		{
			$byLabel[$rec['label']][] = $rec + array('server' => $metrics[$rec['id']] ?? null);
		}
		foreach ($byLabel as $label => $list)
		{
			$col = fn(string $key) => array_values(array_filter(array_map(fn($r) => $r['server'][$key] ?? null, $list), fn($v) => $v !== null));
			$statuses = array_count_values(array_column($list, 'status'));
			ksort($statuses);
			$result[$label][$name] = array(
				'n' => count($list),
				'missing_server_metrics' => count(array_filter($list, fn($r) => $r['server'] === null)),
				'wall_ms' => summarize($col('wall_ms')),
				'cpu_ms' => summarize($col('cpu_ms')),
				'peak_mem' => summarize($col('peak_mem')),
				'files' => percentile($col('files'), 50),
				'classes' => percentile($col('classes'), 50),
				'queries' => percentile($col('queries'), 50),
				'client_ms' => summarize(array_column($list, 'client_ms')),
				'statuses' => $statuses,
				'full_pages' => count(array_filter($list, fn($r) => $r['page'])),
			);
		}
	}
	return $result;
}

function runThroughput(array $cfg, array $sites, array $scenario, string $scName, int $size, int $n, int $concurrency, int $rounds): array
{
	$names = array_keys($sites);
	$samples = array_fill_keys($names, array('rps' => array(), 'latencies' => array(), 'statuses' => array()));
	for ($round = 0; $round < $rounds; $round++)
	{
		$shift = $round % count($names);
		foreach (array_merge(array_slice($names, $shift), array_slice($names, 0, $shift)) as $name)
		{
			prepareSite($sites[$name]['link'], $name, $size);
			$requests = $scenario['batch']($sites[$name], $n, $round);
			// one request to get over any first-request effect after the preparation
			http(baseUrl($sites[$name]) . '/');
			$r = httpConcurrent($requests, $concurrency);
			foreach ($requests as $req)
			{
				if (isset($req['cookies']))
				{
					unlink($req['cookies']);
				}
			}
			$samples[$name]['rps'][] = $r['rps'];
			$samples[$name]['latencies'] = array_merge($samples[$name]['latencies'], $r['latencies']);
			foreach ($r['statuses'] as $code => $count)
			{
				$samples[$name]['statuses'][$code] = ($samples[$name]['statuses'][$code] ?? 0) + $count;
			}
		}
	}
	$result = array();
	foreach ($names as $name)
	{
		ksort($samples[$name]['statuses']);
		$result[$name] = array(
			'rps' => percentile($samples[$name]['rps'], 50),
			'rps_all' => $samples[$name]['rps'],
			'p50' => percentile($samples[$name]['latencies'], 50),
			'p95' => percentile($samples[$name]['latencies'], 95),
			'p99' => percentile($samples[$name]['latencies'], 99),
			'statuses' => $samples[$name]['statuses'],
		);
	}
	return $result;
}

/** What storing failed logins costs in the database. */
function runGrowth(array $sites, int $count, int $concurrency): array
{
	$scenario = scenarios()['login_fail'];
	$result = array();
	foreach ($sites as $name => $site)
	{
		if (!hasBfstop($name))
		{
			continue;
		}
		prepareSite($site['link'], $name, 0);
		$before = tableStats($site['link']);
		$requests = $scenario['batch']($site, $count, 9);
		$r = httpConcurrent($requests, $concurrency);
		foreach ($requests as $req)
		{
			unlink($req['cookies']);
		}
		$result[$name] = array('requests' => $count, 'statuses' => $r['statuses'],
			'before' => $before, 'after' => tableStats($site['link']));
	}
	return $result;
}

/** The queries of bfstop's tables a single request makes, from MariaDB's general log. */
function traceQueries(array $cfg, array $sites, array $scenario): array
{
	$admin = connect($cfg, 'mysql');
	$oldOutput = $admin->query('SELECT @@GLOBAL.log_output')->fetch_row()[0];
	$result = array();
	try
	{
		foreach ($sites as $name => $site)
		{
			$recs = array();
			$state = array();
			// one step of the scenario for warming up, then trace the next one
			$scenario['run']($site, 0, false, $recs, $state);
			$admin->query('SET GLOBAL general_log = 0');
			$admin->query('SET GLOBAL log_output = "TABLE"');
			$admin->query('TRUNCATE TABLE mysql.general_log');
			$admin->query('SET GLOBAL general_log = 1');
			$scenario['run']($site, 1, false, $recs, $state);
			$admin->query('SET GLOBAL general_log = 0');
			$all = $admin->query("SELECT argument FROM mysql.general_log WHERE command_type IN ('Query', 'Prepare') ORDER BY event_time")->fetch_all();
			$queries = array_map(fn($row) => preg_replace('/\s+/', ' ', trim($row[0])), $all);
			$result[$name] = array(
				'total' => count(array_filter($queries, fn($q) => !preg_match('/^(SET GLOBAL|TRUNCATE|SELECT argument FROM mysql\.general_log)/', $q))),
				'bfstop' => array_values(array_filter($queries, fn($q) => stripos($q, 'bfstop') !== false && !str_contains($q, 'general_log'))),
			);
		}
	}
	catch (Throwable $e)
	{
		fwrite(STDERR, "Query trace failed (needs the privileges to switch on the general log): " . $e->getMessage() . "\n");
		$result = array();
	}
	finally
	{
		$admin->query('SET GLOBAL general_log = 0');
		$admin->query("SET GLOBAL log_output = '$oldOutput'");
	}
	return $result;
}

function dirStats(string $dir): array
{
	$files = 0;
	$bytes = 0;
	$phpFiles = 0;
	$phpLines = 0;
	foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $f)
	{
		$files++;
		$bytes += $f->getSize();
		if ($f->getExtension() === 'php')
		{
			$phpFiles++;
			$phpLines += substr_count(file_get_contents($f->getPathname()), "\n");
		}
	}
	return compact('files', 'bytes', 'phpFiles', 'phpLines');
}

function staticFootprint(array $cfg, array $sites): array
{
	$result = array();
	foreach ($sites as $name => $site)
	{
		if (!hasBfstop($name))
		{
			continue;
		}
		$manifest = simplexml_load_file($site['dir'] . '/plugins/system/bfstop/bfstop.xml');
		$tables = tableStats($site['link']);
		// freshly installed, i.e. still empty
		$fresh = array('tables' => count($tables),
			'db_bytes' => array_sum(array_map(fn($t) => $t['data'] + $t['index'], $tables)));
		$result[$name] = array('version' => (string) $manifest->version,
			'package_bytes' => isset($site['package']) ? filesize($site['package']) : null,
			'installed' => dirStats($site['dir'] . '/plugins/system/bfstop')) + $fresh;
	}
	return $result;
}

// ---------------------------------------------------------------------------
// report

function fmt($v, int $decimals = 1): string
{
	if ($v === null || (is_float($v) && is_nan($v)))
	{
		return '-';
	}
	return number_format($v, $decimals, '.', '');
}

function signed($v, int $decimals = 1): string
{
	if ($v === null || (is_float($v) && is_nan($v)))
	{
		return '-';
	}
	return ($v >= 0 ? '+' : '') . number_format($v, $decimals, '.', '');
}

function kib(float $bytes): string
{
	return fmt($bytes / 1024, 1);
}

function mdTable(array $header, array $rows): string
{
	$out = '| ' . implode(' | ', $header) . " |\n";
	$out .= '|' . implode('|', array_map(fn($h, $i) => $i === 0 ? ' --- ' : ' ---: ', $header, array_keys($header))) . "|\n";
	foreach ($rows as $row)
	{
		$out .= '| ' . implode(' | ', $row) . " |\n";
	}
	return $out;
}

function statusText(array $statuses): string
{
	$parts = array();
	foreach ($statuses as $code => $count)
	{
		$parts[] = "{$code}×{$count}";
	}
	return implode(', ', $parts);
}

function renderReport(array $cfg, array $opts, array $env, array $static, array $seq, array $thr, array $growth, array $trace): string
{
	$labels = array_map(fn($s) => $s['label'], $cfg['sites']);
	$base = 'baseline';
	$cur = 'current';
	$out = "# bfstop performance comparison\n\n";
	$out .= "Compared: **{$labels[$base]}** (the \"baseline\") and **{$labels[$cur]}**, " .
		"each in an otherwise identical Joomla {$cfg['joomla']} site, against a site without bfstop.\n\n";
	$out .= "## Environment\n\n" . mdTable(array('', ''), array_map(null, array_keys($env), array_values($env))) . "\n";
	$out .= "Server-side numbers come from the web server's own view of a request (time from the start of the " .
		"script until its end, CPU time of the process, PHP's peak memory, number of PHP files loaded and SQL queries " .
		"run by Joomla's database driver), requests are made one at a time, the three sites taking turns. " .
		"\"Overhead\" is a variant's median minus the median of the site without bfstop.\n\n";

	$out .= "## Installed footprint\n\n";
	$rows = array();
	foreach ($static as $name => $s)
	{
		$rows[] = array($labels[$name], $s['version'], fmt($s['package_bytes'] / 1024), $s['installed']['files'],
			kib($s['installed']['bytes']), $s['installed']['phpFiles'], $s['installed']['phpLines'],
			$s['tables'], kib($s['db_bytes']));
	}
	$out .= mdTable(array('', 'version', 'zip KiB', 'files', 'installed KiB', 'PHP files', 'PHP lines', 'DB tables', 'empty tables KiB'), $rows) . "\n";

	// requests which bfstop answers itself instead of Joomla: not comparable to what
	// a site without bfstop does with them (it renders the page)
	$answeredByBfstop = array('home_blocked', 'attack_rejected', 'attack_block');
	$out .= "## Overhead per request\n\n";
	$out .= "Median over the requests of each scenario, bfstop minus no bfstop. Each cell: " .
		"`{$labels[$base]}` / `{$labels[$cur]}`. Queries, PHP files and memory are deterministic; " .
		"differences in time of a millisecond or two are within the noise of a shared machine " .
		"(see the details below for the spread).\n\n";
	$rows = array();
	$rowsBlocked = array();
	foreach ($seq as $size => $scenarioResults)
	{
		foreach ($scenarioResults as $scName => $byLabel)
		{
			foreach ($byLabel as $label => $bySite)
			{
				if (!isset($bySite[$base], $bySite[$cur]))
				{
					continue;
				}
				if (in_array($label, $answeredByBfstop) || !isset($bySite['none']))
				{
					$a = function (string $key, ?string $sub, int $dec = 1, float $div = 1) use ($bySite) {
						$get = fn($name) => ($sub === null ? $bySite[$name][$key] : $bySite[$name][$key][$sub]) / $div;
						return fmt($get('baseline'), $dec) . ' / ' . fmt($get('current'), $dec);
					};
					$rowsBlocked[] = array(number_format($size), $label, $a('wall_ms', 'median', 2), $a('cpu_ms', 'median', 2),
						$a('queries', null, 0), $a('files', null, 0), $a('peak_mem', 'median', 1, 1024));
					continue;
				}
				$d = function (string $key, ?string $sub, int $dec = 1, float $div = 1) use ($bySite) {
					$get = fn($name) => ($sub === null ? $bySite[$name][$key] : $bySite[$name][$key][$sub]) / $div;
					return signed($get('baseline') - $get('none'), $dec) . ' / ' . signed($get('current') - $get('none'), $dec);
				};
				$rows[] = array(number_format($size), $label, $d('wall_ms', 'median', 2), $d('cpu_ms', 'median', 2),
					$d('queries', null, 0), $d('files', null, 0), $d('peak_mem', 'median', 1, 1024));
			}
		}
	}
	$out .= mdTable(array('table rows', 'request', 'Δ time ms', 'Δ CPU ms', 'Δ queries', 'Δ PHP files', 'Δ peak mem KiB'), $rows) . "\n";
	$out .= "The tables are filled with that many failed logins, and a tenth of that many blocks (mostly expired).\n\n";
	$out .= "### Requests bfstop itself answers\n\n" .
		"A blocked client gets bfstop's short message, Joomla stops before rendering the page, so there is no " .
		"overhead to speak of: the absolute cost of the request (`{$labels[$base]}` / `{$labels[$cur]}`). " .
		"`attack_block` is the failed login which leads to the block.\n\n";
	$out .= mdTable(array('table rows', 'request', 'time ms', 'CPU ms', 'queries', 'PHP files', 'peak mem KiB'), $rowsBlocked) . "\n";

	$out .= "## Details per request\n\n";
	foreach ($seq as $size => $scenarioResults)
	{
		foreach ($scenarioResults as $scName => $byLabel)
		{
			foreach ($byLabel as $label => $bySite)
			{
				$out .= "### `$label`, " . number_format($size) . " failed logins in the tables\n\n";
				$rows = array();
				foreach ($bySite as $name => $r)
				{
					$rows[] = array($labels[$name], $r['n'], fmt($r['wall_ms']['median'], 2), fmt($r['wall_ms']['p95'], 2),
						fmt($r['cpu_ms']['median'], 2), kib($r['peak_mem']['median']), fmt($r['files'], 0),
						fmt($r['classes'], 0), fmt($r['queries'], 0), fmt($r['client_ms']['median'], 2),
						statusText($r['statuses']) . ($r['full_pages'] ? " ({$r['full_pages']} full pages)" : ''));
				}
				$out .= mdTable(array('', 'n', 'time median ms', 'time p95 ms', 'CPU median ms', 'peak mem KiB',
					'PHP files', 'classes', 'queries', 'client median ms', 'HTTP status'), $rows) . "\n";
			}
		}
	}

	if ($thr)
	{
		$out .= "## Throughput\n\nSeveral requests at the same time ({$opts['concurrency']} clients, {$opts['workers']} PHP workers, " .
			"{$opts['throughput']} requests per round, median of {$opts['rounds']} rounds, client and server share the machine).\n\n";
		$rows = array();
		foreach ($thr as $size => $byScenario)
		{
			foreach ($byScenario as $scName => $bySite)
			{
				foreach ($bySite as $name => $r)
				{
					$rows[] = array(number_format($size), $scName, $labels[$name], fmt($r['rps']), fmt($r['p50']),
						fmt($r['p95']), fmt($r['p99']), statusText($r['statuses']));
				}
			}
		}
		$out .= mdTable(array('table rows', 'request', '', 'requests/s', 'p50 ms', 'p95 ms', 'p99 ms', 'HTTP status'), $rows) . "\n";
	}

	if ($growth)
	{
		$out .= "## Database growth\n\nAfter {$opts['growth']} failed logins (each from another address, with another user name), " .
			"starting from empty tables. The sizes are in units of InnoDB pages (16 KiB), so look at the average " .
			"row length for small tables.\n\n";
		$rows = array();
		$summary = array();
		foreach ($growth as $name => $g)
		{
			$total = 0;
			foreach ($g['after'] as $table => $after)
			{
				$total += $after['data'] + $after['index'] - ($g['before'][$table]['data'] + $g['before'][$table]['index']);
				$rows[] = array($labels[$name], $table, $after['rows'], $after['avg_row'], kib($after['data']), kib($after['index']));
			}
			$summary[] = array($labels[$name], kib($total), fmt($total / max(1, $g['requests']), 0));
		}
		$out .= mdTable(array('', 'table', 'rows', 'avg row bytes', 'data KiB', 'index KiB'), $rows) . "\n";
		$out .= mdTable(array('', 'growth KiB', 'bytes per failed login'), $summary) . "\n";
	}

	if ($trace)
	{
		$out .= "## Queries of bfstop's tables\n\nWhat a single request sends to the database (MariaDB general log, empty tables).\n\n";
		foreach ($trace as $scName => $bySite)
		{
			foreach ($bySite as $name => $t)
			{
				if (!hasBfstop($name))
				{
					continue;
				}
				$out .= "### `$scName`, {$labels[$name]}: " . count($t['bfstop']) . " of {$t['total']} queries" .
					($scName === 'login_fail' ? " (the login form and the failed login)" : '') . "\n\n";
				foreach ($t['bfstop'] as $q)
				{
					$out .= '- `' . str_replace('`', '', mb_strimwidth($q, 0, 220, '…')) . "`\n";
				}
				$out .= "\n";
			}
		}
	}
	return $out;
}

// ---------------------------------------------------------------------------

function main(array $argv): int
{
	$o = getopt('', array('sites:', 'out:', 'requests:', 'warmup:', 'sizes:', 'scenarios:', 'throughput:',
		'concurrency:', 'workers:', 'rounds:', 'growth:', 'quick', 'no-trace', 'help'));
	if (isset($o['help']))
	{
		echo "Usage: php bench.php [--sites=sites.json] [--out=dir] [--requests=200] [--warmup=20]\n" .
			"  [--sizes=0,100000] [--scenarios=" . implode(',', array_keys(scenarios())) . "]\n" .
			"  [--throughput=400] [--concurrency=8] [--workers=4] [--rounds=3] [--growth=2000] [--quick] [--no-trace]\n";
		return 0;
	}
	$quick = isset($o['quick']);
	$benchDir = getenv('BENCH_DIR') ?: '/tmp/bfstop-perf';
	$opts = array(
		'requests' => (int) ($o['requests'] ?? ($quick ? 40 : 200)),
		'warmup' => (int) ($o['warmup'] ?? ($quick ? 5 : 20)),
		'throughput' => (int) ($o['throughput'] ?? ($quick ? 80 : 400)),
		'concurrency' => (int) ($o['concurrency'] ?? 8),
		'workers' => (int) ($o['workers'] ?? 4),
		'rounds' => (int) ($o['rounds'] ?? ($quick ? 1 : 3)),
		'growth' => (int) ($o['growth'] ?? ($quick ? 500 : 2000)),
	);
	$sizes = array_map('intval', explode(',', $o['sizes'] ?? ($quick ? '0,10000' : '0,100000')));
	$scenarios = scenarios();
	$selected = isset($o['scenarios']) ? explode(',', $o['scenarios']) : array_keys($scenarios);
	foreach ($selected as $s)
	{
		if (!isset($scenarios[$s]))
		{
			fwrite(STDERR, "Unknown scenario $s\n");
			return 1;
		}
	}
	$cfg = json_decode(file_get_contents($o['sites'] ?? "$benchDir/sites.json"), true);
	$outDir = $o['out'] ?? "$benchDir/results/" . date('Ymd-His');
	@mkdir($outDir, 0777, true);

	$sites = array();
	foreach ($cfg['sites'] as $name => $site)
	{
		$sites[$name] = $site + array('name' => $name, 'link' => connect($cfg, $site['db']));
	}

	$servers = array();
	$start = function (int $workers) use (&$servers, $sites, $outDir) {
		foreach ($sites as $name => $site)
		{
			$metrics = "$outDir/metrics-$name.jsonl";
			$servers[$name] = startServer($site, $workers, $metrics) + array('metrics' => $metrics);
		}
	};
	$stop = function () use (&$servers) {
		foreach ($servers as $s)
		{
			stopServer($s);
		}
		$servers = array();
	};
	register_shutdown_function($stop);
	pcntl_async_signals(true);
	foreach (array(SIGINT, SIGTERM) as $sig)
	{
		pcntl_signal($sig, function () use ($stop) {
			$stop();
			exit(130);
		});
	}

	$admin = connect($cfg, 'mysql');
	$env = array(
		'date' => date('Y-m-d H:i:s T'),
		'PHP' => PHP_VERSION . ', opcache on (no timestamp validation), built-in web server',
		'Joomla' => $cfg['joomla'],
		'database' => $admin->query('SELECT VERSION()')->fetch_row()[0],
		'machine' => php_uname('s r m') . ', ' . trim((string) shell_exec('nproc')) . ' CPUs',
		'requests per scenario' => "{$opts['requests']} (after {$opts['warmup']} warm-up requests)",
		'table sizes (failed logins)' => implode(', ', array_map('number_format', $sizes)),
	);

	$static = staticFootprint($cfg, $sites);
	$seq = array();
	$thr = array();
	$growth = array();
	$trace = array();

	echo "Sequential measurements\n";
	$start(1);
	foreach ($sizes as $size)
	{
		foreach ($selected as $scName)
		{
			echo "  $scName with $size rows: ";
			foreach ($sites as $name => $site)
			{
				prepareSite($site['link'], $name, $size);
				// the first request after changing the database is not representative
				http(baseUrl($site) . '/');
			}
			$seq[$size][$scName] = runSequential($sites, $servers, $scenarios[$scName], $opts['requests'], $opts['warmup']);
			echo "done\n";
		}
	}
	if (!isset($o['no-trace']))
	{
		echo "Tracing queries\n";
		foreach ($sites as $name => $site)
		{
			prepareSite($site['link'], $name, 0);
		}
		foreach (array('home', 'home_blocked', 'login_fail') as $scName)
		{
			if (in_array($scName, $selected))
			{
				$trace[$scName] = traceQueries($cfg, $sites, $scenarios[$scName]);
			}
		}
	}
	$stop();

	if ($opts['throughput'] > 0)
	{
		echo "Throughput measurements\n";
		$start($opts['workers']);
		foreach ($sizes as $size)
		{
			foreach ($selected as $scName)
			{
				if ($scenarios[$scName]['batch'] === null)
				{
					continue;
				}
				echo "  $scName with $size rows: ";
				$thr[$size][$scName] = runThroughput($cfg, $sites, $scenarios[$scName], $scName, $size,
					$opts['throughput'], $opts['concurrency'], $opts['rounds']);
				echo "done\n";
			}
		}
		if ($opts['growth'] > 0)
		{
			echo "Database growth\n";
			$growth = runGrowth($sites, $opts['growth'], $opts['concurrency']);
		}
		$stop();
	}

	file_put_contents("$outDir/results.json", json_encode(compact('env', 'opts', 'static', 'seq', 'thr', 'growth', 'trace'),
		JSON_PRETTY_PRINT | JSON_PARTIAL_OUTPUT_ON_ERROR));
	$report = renderReport($cfg, $opts, $env, $static, $seq, $thr, $growth, $trace);
	file_put_contents("$outDir/report.md", $report);
	echo "\n$report\nResults in $outDir\n";
	return 0;
}

exit(main($argv));
