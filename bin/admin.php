<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli') { http_response_code(404); exit; }
define('VEGADNS_INTERNAL',true);
require dirname(__DIR__).'/src/bootstrap.php';
try {
    $config=require dirname(__DIR__).'/src/config.php';
    $db=new \VegaDNS\DB(new PDO($config['dsn'],$config['db_user'],$config['db_password']));
    $command=$argv[1]??'';
    if($command==='migrate') { \VegaDNS\Schema::migrate($db); echo "Migration complete. Existing sessions have been revoked.\n"; }
    elseif($command==='create-admin' || $command==='set-password') {
        $email=\VegaDNS\Security::email($argv[2]??'');
        fwrite(STDERR,"Reading password from standard input (12–72 bytes); do not put it in command arguments.\n");
        $hash=\VegaDNS\Security::password(rtrim(stream_get_contents(STDIN),"\r\n"));
        if($command==='create-admin') $db->run("INSERT INTO accounts (Email,Password,First_Name,Last_Name,Account_Type,Status,gid,auth_version) VALUES (?,?,'System','Administrator','senior_admin','active',0,1)",[$email,$hash]);
        else {
            $db->transaction(function() use($db,$email,$hash) {
                $user=$db->one('SELECT cid FROM accounts WHERE Email=?',[$email]); if(!$user) throw new RuntimeException('Account not found');
                $db->run("UPDATE accounts SET Password=?,Status='active',auth_version=auth_version+1 WHERE cid=?",[$hash,$user['cid']]);
                $db->run('DELETE FROM password_resets WHERE cid=?',[$user['cid']]);
            });
        }
        echo "Account provisioned; affected sessions are invalid.\n";
    } elseif($command==='check-export') { $data=(new \VegaDNS\Store($db))->export(); echo 'Validated '.strlen($data)." export bytes.\n"; }
    elseif($command==='cleanup') {
        $db->run('DELETE FROM auth_limits WHERE started<?',[time()-86400]); $db->run('DELETE FROM password_resets WHERE expires<?',[time()]); $db->run('DELETE FROM web_sessions WHERE access<?',[time()-$config['timeout']]); echo "Expired security state removed.\n";
    } else { fwrite(STDERR,"Usage: php bin/admin.php migrate|create-admin EMAIL|set-password EMAIL|check-export|cleanup\n"); exit(2); }
} catch(Throwable $e) { fwrite(STDERR,'Operation failed: '.get_class($e).". Check configuration, schema and input; database errors are not printed.\n"); exit(1); }
