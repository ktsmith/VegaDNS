<?php
declare(strict_types=1);
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }
$env=static fn(string $key,string $default=''): string => getenv($key)===false?$default:getenv($key);
$base=$env('VEGADNS_BASE_URL'); $parts=parse_url($base);
if(!$parts || ($parts['scheme']??'')!=='https' || !isset($parts['host']) || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment']) || !str_ends_with($parts['path']??'','/index.php') || preg_match('/[\x00-\x20\x7f]/',$base)) throw new RuntimeException('Configure a canonical HTTPS VEGADNS_BASE_URL ending in /index.php');
$support=\VegaDNS\Security::email($env('VEGADNS_SUPPORT_EMAIL'));
$list=static fn(string $key): array => array_values(array_filter(array_map('trim',explode(',',$env($key)))));
$servers=$list('VEGADNS_DNS_SERVERS'); $proxies=$list('VEGADNS_TRUSTED_PROXIES');
foreach(array_merge($servers,$proxies) as $ip) if(!filter_var($ip,FILTER_VALIDATE_IP)) throw new RuntimeException('Network allowlists must contain IP literals');
$dsn=$env('VEGADNS_DSN');
if(!str_starts_with($dsn,'mysql:') || !str_contains($dsn,'charset=utf8mb4')) throw new RuntimeException('Configure a MySQL DSN with charset=utf8mb4');
$sessions=$env('VEGADNS_SESSIONS','files');
if(!in_array($sessions,['files','mysql'],true)) throw new RuntimeException('Invalid session backend');
return ['base_url'=>$base,'cookie_path'=>rtrim(dirname($parts['path']),'/').'/',
    'dsn'=>$dsn,'db_user'=>$env('VEGADNS_DB_USER'),'db_password'=>$env('VEGADNS_DB_PASSWORD'),
    'support_email'=>$support,'timeout'=>3600,'sessions'=>$sessions,
    'session_dir'=>$env('VEGADNS_SESSION_DIR','/var/lib/vegadns/sessions'),
    'transfer_dir'=>$env('VEGADNS_TRANSFER_DIR','/var/lib/vegadns/transfers'),
    'tools'=>$env('VEGADNS_DNS_TOOLS','/usr/local/bin'),'dns_servers'=>$servers,
    'trusted_proxies'=>$proxies,'export_token'=>$env('VEGADNS_EXPORT_TOKEN')];
