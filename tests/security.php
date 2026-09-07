<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('VEGADNS_INTERNAL', true);
require dirname(__DIR__).'/src/bootstrap.php';
use VegaDNS\{DB,Schema,Security,Auth,Store,DNS,View,Network,Sessions,HttpError};

$checks=0;
function check(bool $ok,string $message): void { global $checks; ++$checks; if(!$ok) throw new RuntimeException($message); }
function denied(callable $action,int $status=400): void {
    try { $action(); } catch(HttpError $e) { check($e->status===$status,'Unexpected rejection: '.$e->getMessage()); return; }
    throw new RuntimeException('Unsafe operation was accepted');
}
$temp=sys_get_temp_dir().'/vegadns-test-'.bin2hex(random_bytes(8)); mkdir($temp,0700);
ini_set('error_log',$temp.'/audit.log');
$dsn=getenv('VEGADNS_TEST_DSN') ?: 'sqlite::memory:';
if($dsn!=='sqlite::memory:' && !preg_match('/\Amysql:.*dbname=vegadns_test(?:;|$)/',$dsn)) throw new RuntimeException('Tests require an isolated vegadns_test database');
$db=new DB(new PDO($dsn,getenv('VEGADNS_TEST_USER')?:null,getenv('VEGADNS_TEST_PASSWORD')?:null));
if($db->pdo->getAttribute(PDO::ATTR_DRIVER_NAME)==='mysql' && $db->all('SHOW TABLES')) throw new RuntimeException('Test database must be empty');
$config=['timeout'=>3600,'cookie_path'=>'/','sessions'=>'files','session_dir'=>$temp,'base_url'=>'https://dns.example/index.php','dns_servers'=>['192.0.2.53']];
try {
    Schema::migrate($db);
    check(!$db->one('SELECT * FROM accounts'),'Migration must not provision a default administrator');
    Security::startSession($config,$db);
    check(session_get_cookie_params()['secure'] && session_get_cookie_params()['httponly'],'Secure cookie flags');
    check(ini_get('session.use_only_cookies')==='1' && ini_get('session.use_strict_mode')==='1','Strict cookie sessions');
    $store=new Store($db); $auth=new Auth($db,$config);
    $seed=function(string $email,string $role,int $group=0) use($db): array {
        $db->run('INSERT INTO accounts (Email,Password,First_Name,Last_Name,Account_Type,Status,gid) VALUES (?,?,?,?,?,?,?)',[$email,md5('legacy-password'),'<script>','O\'Brien',$role,'active',$group]);
        return $db->one('SELECT * FROM accounts WHERE cid=?',[$db->pdo->lastInsertId()]);
    };
    $senior=$seed('admin@example.test','senior_admin'); $group=$seed('group@example.test','group_admin');
    $alice=$seed('alice@example.test','user',(int)$group['cid']); $bob=$seed('bob@example.test','user');
    $soa=['type'=>'S','host'=>'hostmaster.DOMAIN:ns1.example.test','val'=>'16384:2048:1048576:2560:','ttl'=>3600];
    $store->saveDefault($senior,null,$soa);
    $payload="O'Brien : \\ \n<script>alert(1)</script> mydomain.test";
    $store->saveDefault($senior,null,['type'=>'T','host'=>'txt.DOMAIN','val'=>$payload,'ttl'=>60]);
    $a=$store->addDomain($alice,'alice.test'); $b=$store->addDomain($bob,'bob.test');
    $copied=$db->one("SELECT * FROM records WHERE domain_id=? AND type='T'",[$a]);
    check($copied['val']===$payload && $copied['host']==='txt.alice.test','Bound second-order defaults and label replacement');
    $foreign=$db->one("SELECT record_id FROM records WHERE domain_id=? AND type='T'",[$b]);
    denied(fn()=>$store->deleteRecord($alice,$a,(int)$foreign['record_id']),404);
    denied(fn()=>$store->record($alice,$a,(int)$foreign['record_id']),404);
    denied(fn()=>$store->domain($alice,$b),404);
    denied(fn()=>$store->account($group,(int)$bob['cid']),404);
    check(count($store->domains($alice,[]))===1,'Tenant domain filtering');
    denied(fn()=>$store->domains($alice,['sortfield'=>'domain DESC; DELETE FROM accounts']));
    denied(fn()=>$store->domains($alice,['scope'=>"a' OR 1=1 --"]));
    denied(fn()=>Security::integer('1 OR 1=1'));
    denied(fn()=>Security::text(['id'=>['1']],'id'));
    $row=['type'=>'T','host'=>'text.alice.test','val'=>$payload,'ttl'=>0];
    $store->saveRecord($alice,$a,null,$row);
    $record=(int)$db->pdo->lastInsertId();
    // log has no generated key; obtain the record by its scoped owner name.
    $record=(int)$db->one('SELECT record_id FROM records WHERE domain_id=? AND host=?',[$a,$row['host']])['record_id'];
    $row['val'].=" ' UNION SELECT"; $store->saveRecord($alice,$a,$record,$row);
    check($store->record($alice,$a,$record)['val']===$row['val'],'TXT SQL payload stays data through update');
    $store->deleteRecord($alice,$a,$record);
    check($db->one('SELECT record_id FROM records WHERE record_id=?',[$foreign['record_id']])!==null,'Foreign row preserved');
    $soaId=(int)$db->one("SELECT record_id FROM records WHERE domain_id=? AND type='S'",[$a])['record_id'];
    denied(fn()=>$store->deleteRecord($alice,$a,$soaId));
    denied(fn()=>DNS::record(['type'=>'T','host'=>"x.alice.test\n+outside.test:192.0.2.1",'val'=>'x'],'alice.test'));
    denied(fn()=>DNS::record(['type'=>'T','host'=>'evilalice.test','val'=>'x'],'alice.test'));
    denied(fn()=>DNS::name('alice.test..'));
    denied(fn()=>DNS::owner('foreign.test.','alice.test'));
    $wire=DNS::export($copied,'alice.test');
    check(substr_count($wire,"\n")===1 && !str_contains($wire,'<script>'),'TXT serialized as one physical line');
    $types=[['type'=>'A','host'=>'a.alice.test','val'=>'192.0.2.1'],['type'=>'3','host'=>'v6.alice.test','val'=>'2001:db8::1'],['type'=>'N','host'=>'alice.test','val'=>'ns.example.test'],['type'=>'M','host'=>'alice.test','val'=>'mx.example.test','distance'=>10],['type'=>'C','host'=>'alias.alice.test','val'=>'a.alice.test'],['type'=>'V','host'=>'_sip._tcp.alice.test','val'=>'sip.example.test','distance'=>10,'weight'=>20,'port'=>5060],['type'=>'F','host'=>'alice.test','val'=>'v=spf1 -all'],$copied];
    $soaActual=DNS::record(['type'=>'S','host'=>'hostmaster.alice.test:ns.example.test','val'=>'16384:2048:1048576:2560:4294967295'],'alice.test');
    foreach($types as $r) {
        $normalized=DNS::record($r,'alice.test');
        $round=DNS::import(DNS::export($soaActual,'alice.test').DNS::export($r,'alice.test'),'alice.test');
        check($round[1]===$normalized,'DNS round trip '.$r['type']);
    }
    check(DNS::reverse('192.0.2.1')==='1.2.0.192.in-addr.arpa','IPv4 reverse');
    check(str_ends_with(DNS::reverse('2001:db8::1'),'.ip6.arpa'),'IPv6 reverse');
    denied(fn()=>$store->saveRecord($alice,$a,null,['type'=>'=','host'=>'a.alice.test','val'=>'192.0.2.1']));
    $store->status($senior,$a,'active'); $store->status($senior,$b,'active');
    check(str_contains($store->export(),'#alice.test'),'Complete export');
    $db->run('UPDATE records SET host=? WHERE record_id=?',["bad\nhost",$copied['record_id']]);
    denied(fn()=>$store->export());
    $db->run('UPDATE records SET host=? WHERE record_id=?',[$copied['host'],$copied['record_id']]);
    $html=View::page('<script>',[View::table(['<img>'],[[$payload]]),View::form(['state'=>'login'],['password'=>['Password',$payload,'password']],'Sign in')]);
    check(!str_contains($html,'<script>') && str_contains($html,'&lt;script&gt;'),'Text and attribute output encoding');
    check(str_contains($html,'method="post"') && str_contains($html,'name="csrf"') && !str_contains($html,'VDNSSessid'),'POST forms with CSRF and no URL session');
    denied(fn()=>Security::requirePost('GET',['csrf'=>Security::csrf()]),405);
    denied(fn()=>Security::requirePost('POST',['csrf'=>'wrong']),403);
    Security::requirePost('POST',['csrf'=>Security::csrf()]);
    Security::requireOrigin('https://dns.example',$config['base_url']);
    denied(fn()=>Security::requireOrigin('https://attacker.test',$config['base_url']),403);
    $before=session_id();
    check($auth->login($alice['Email'],'legacy-password','192.0.2.1'),'Legacy password login');
    check($before!==session_id(),'Session rotated at login');
    $hash=$db->one('SELECT Password FROM accounts WHERE cid=?',[$alice['cid']])['Password'];
    check(password_verify('legacy-password',$hash) && strlen($hash)>32,'Legacy MD5 upgraded');
    check($auth->current()!==null,'Current authenticated account');
    $url=''; $auth->requestReset($alice['Email'],'192.0.2.1',function($to,$link) use(&$url) { $url=$link; });
    check($db->one('SELECT Password FROM accounts WHERE cid=?',[$alice['cid']])['Password']===$hash,'Reset request does not alter password');
    parse_str(parse_url($url,PHP_URL_QUERY),$query); $token=$query['token'];
    check($db->one('SELECT token_hash FROM password_resets')['token_hash']===hash('sha256',$token),'Only reset digest stored');
    $oldSession=$_SESSION;
    check($auth->reset($token,'new-secure-password'),'Valid reset consumed');
    check(!$auth->reset($token,'another-password'),'Reset replay denied');
    $_SESSION=$oldSession; check($auth->current()===null,'Reset revokes existing sessions');
    $expired=str_repeat('a',64); $db->run('INSERT INTO password_resets VALUES (?,?,?)',[hash('sha256',$expired),$alice['cid'],time()-1]);
    check(!$auth->reset($expired,'expired-password'),'Expired reset rejected');
    check($auth->limit('test','same',1,60) && !$auth->limit('test','same',1,60),'Shared rate limiting');
    check(!$auth->login("' OR 1=1 --",'legacy-password','192.0.2.2'),'Login injection denied');
    check($auth->login($bob['Email'],'legacy-password','192.0.2.2'),'Second tenant login');
    $store->deleteAccount($senior,(int)$bob['cid']);
    check(!$db->one('SELECT cid FROM accounts WHERE cid=?',[$bob['cid']]),'Account really deleted');
    check($auth->current()===null && !$auth->login($bob['Email'],'legacy-password','192.0.2.2'),'Deleted account cannot keep session or log in');
    check($auth->login($alice['Email'],'new-secure-password','192.0.2.3'),'New reset password authenticates');
    $accountInput=['email_address'=>$alice['Email'],'first_name'=>'Alice','last_name'=>'Tester','phone'=>'','password'=>'','password2'=>'','account_type'=>'user','status'=>'inactive','gid'=>(string)$group['cid']];
    $store->saveAccount($senior,(int)$alice['cid'],$accountInput);
    check($auth->current()===null && !$auth->login($alice['Email'],'new-secure-password','192.0.2.3'),'Deactivation revokes sessions and new login');
    $accountInput['status']='active'; $store->saveAccount($senior,(int)$alice['cid'],$accountInput);
    check($auth->login($alice['Email'],'new-secure-password','192.0.2.3'),'Reactivated account authenticates');
    $accountInput['password']=$accountInput['password2']='changed-password-123';
    $store->saveAccount($senior,(int)$alice['cid'],$accountInput);
    check($auth->current()===null,'Administrative password change revokes session');
    check((int)$db->one('SELECT owner_id FROM domains WHERE domain_id=?',[$b])['owner_id']===0,'Deleted account ownership reassigned');
    $network=new Network($config);
    check($network->destination('192.0.2.53')==='192.0.2.53','Allowlisted address pinned');
    denied(fn()=>$network->destination('127.0.0.1'),403);
    denied(fn()=>$network->destination('example.test;touch pwned'));
    $sessions=new Sessions($db);
    check(!$sessions->validateId('unknown'),'Database strict session validation');
    $sessions->write('KnownId','encoded-session');
    check($sessions->validateId('KnownId') && !$sessions->validateId('knownid'),'Session IDs are case sensitive');
    check($sessions->read('KnownId')==='encoded-session','Database session persistence');
    $sessions->destroy('KnownId'); check(!$sessions->validateId('KnownId'),'Database session deletion');
    $db->run("INSERT INTO accounts (Email,Password,First_Name,Last_Name,Account_Type,Status) VALUES (?,?,'Test','User','senior_admin','active')",['test@test.com',md5('test')]);
    Schema::migrate($db);
    check($db->one('SELECT Status FROM accounts WHERE Email=?',['test@test.com'])['Status']==='inactive','Migration disables shipped default credential');
    echo "PASS: $checks security regression checks (".$db->pdo->getAttribute(PDO::ATTR_DRIVER_NAME).")\n";
} finally {
    if(session_status()===PHP_SESSION_ACTIVE) { $_SESSION=[]; session_destroy(); }
    foreach(glob($temp.'/*') as $file) unlink($file); rmdir($temp);
}
