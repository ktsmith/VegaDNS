<?php
declare(strict_types=1);
define('VEGADNS_INTERNAL', true);
ini_set('display_errors','0'); ini_set('display_startup_errors','0'); ini_set('log_errors','1');
error_reporting(E_ALL);
header('Content-Type: text/html; charset=UTF-8');
header('Cache-Control: no-store'); header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff'); header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
header('Strict-Transport-Security: max-age=31536000');
try {
    require __DIR__.'/src/bootstrap.php';
    $config=require __DIR__.'/src/config.php';
    if (!empty($_SERVER['PATH_INFO'])) throw new \VegaDNS\HttpError(404,'Page not found.');
    $https=($_SERVER['HTTPS']??'')==='on';
    if(!$https && in_array($_SERVER['REMOTE_ADDR']??'', $config['trusted_proxies'],true)) $https=($_SERVER['HTTP_X_FORWARDED_PROTO']??'')==='https';
    if(!$https) throw new \VegaDNS\HttpError(400,'HTTPS is required.');
    $db=new \VegaDNS\DB(new PDO($config['dsn'],$config['db_user'],$config['db_password']));
    (new \VegaDNS\Application($db,$config))->run();
} catch (\VegaDNS\HttpError $e) {
    http_response_code($e->status);
    if($e->status===405) header('Allow: GET, POST');
    \VegaDNS\Security::audit('request_rejected');
    echo \VegaDNS\View::page('Request could not be completed',[$e->getMessage(),\VegaDNS\View::link('Return to VegaDNS',['state'=>'logged_in'])]);
} catch (Throwable $e) {
    http_response_code(503);
    error_log('VegaDNS service failure: '.get_class($e));
    echo 'VegaDNS is unavailable. Ask the operator to check configuration and database migration status.';
}
