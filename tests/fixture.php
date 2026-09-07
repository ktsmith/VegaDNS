<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli') { http_response_code(404); exit; }
define('VEGADNS_INTERNAL',true);
require dirname(__DIR__).'/src/bootstrap.php';
$path=getenv('VEGADNS_HTTP_TEST_DB');
if(!$path || file_exists($path)) throw new RuntimeException('A new temporary database is required');
$db=new VegaDNS\DB(new PDO('sqlite:'.$path));
VegaDNS\Schema::migrate($db);
foreach(['alice','bob'] as $name) $db->run("INSERT INTO accounts (Email,Password,First_Name,Last_Name,Account_Type,Status) VALUES (?,?,?,'Tester','user','active')",[$name.'@example.test',password_hash('test-password-123',PASSWORD_DEFAULT),$name]);
$db->run("INSERT INTO default_records (host,type,val,default_type) VALUES ('hostmaster.DOMAIN:ns.example.test','S','16384:2048:1048576:2560:','system')");
$store=new VegaDNS\Store($db);
foreach($db->all('SELECT * FROM accounts') as $user) {
    $id=$store->addDomain($user,$user['First_Name'].'.test');
    $store->saveRecord($user,$id,null,['host'=>'txt.'.$user['First_Name'].'.test','type'=>'T','val'=>'<script>alert(1)</script>']);
}
