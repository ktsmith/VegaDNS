<?php
declare(strict_types=1);
// Test harness only: no production configuration or credentials are loaded.
if(PHP_SAPI!=='cli-server' || !getenv('VEGADNS_HTTP_TEST_DB') || !in_array($_SERVER['REMOTE_ADDR']??'',['127.0.0.1','::1'],true)) { http_response_code(404); exit; }
if(parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH)!=='/index.php') { http_response_code(404); exit; }
define('VEGADNS_INTERNAL',true);
require dirname(__DIR__).'/src/bootstrap.php';
$config=['timeout'=>3600,'cookie_path'=>'/','sessions'=>getenv('VEGADNS_HTTP_TEST_BACKEND')?:'files','session_dir'=>getenv('VEGADNS_HTTP_TEST_SESSIONS'),'base_url'=>'https://dns.example/index.php','dns_servers'=>[],'tools'=>'/nonexistent','transfer_dir'=>'/nonexistent','export_token'=>str_repeat('x',64)];
ini_set('display_errors','0');
header('Content-Type: text/html; charset=UTF-8');
try { (new VegaDNS\Application(new VegaDNS\DB(new PDO('sqlite:'.getenv('VEGADNS_HTTP_TEST_DB'))),$config))->run(); }
catch(VegaDNS\HttpError $e) { http_response_code($e->status); echo VegaDNS\View::page('Rejected',[$e->getMessage()]); }
catch(Throwable $e) { http_response_code(500); error_log((string)$e); echo 'Test server failure'; }
