<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
/**
 * Used as auto_prepend_file of the PHP built-in web server running a
 * benchmark site (see bench.php): appends one JSON line per request to the
 * file named by BENCH_METRICS_FILE, with what the request cost on the server
 * side (no client, network or connection setup in there).
 */
$benchStart = array(
	'time' => microtime(true),
	'ru'   => getrusage(),
);

register_shutdown_function(function () use ($benchStart) {
	$file = getenv('BENCH_METRICS_FILE');
	if (!$file)
	{
		return;
	}
	$ru = getrusage();
	$cpu = function ($r) {
		return $r['ru_utime.tv_sec'] * 1000 + $r['ru_utime.tv_usec'] / 1000
			+ $r['ru_stime.tv_sec'] * 1000 + $r['ru_stime.tv_usec'] / 1000;
	};
	$queries = null;
	try
	{
		// Joomla's database driver counts the queries it executed
		$queries = \Joomla\CMS\Factory::getContainer()->get('DatabaseDriver')->getCount();
	}
	catch (\Throwable $e)
	{
		// not a Joomla request, or Joomla did not get that far
	}
	$line = json_encode(array(
		'id'       => (int) ($_SERVER['HTTP_X_BENCH_ID'] ?? 0),
		'status'   => http_response_code(),
		'ip'       => $_SERVER['REMOTE_ADDR'] ?? '',
		'wall_ms'  => (microtime(true) - $benchStart['time']) * 1000,
		'cpu_ms'   => $cpu($ru) - $cpu($benchStart['ru']),
		// "real" = what PHP got from the OS (chunks), the other one what scripts allocated
		'peak_mem' => memory_get_peak_usage(false),
		'peak_mem_real' => memory_get_peak_usage(true),
		'files'    => count(get_included_files()),
		'classes'  => count(get_declared_classes()),
		'queries'  => $queries,
	));
	file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
});
