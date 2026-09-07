<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Schema
{
    public static function migrate(DB $db): void {
        $mysql=$db->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME)==='mysql';
        $id=$mysql?'INT NOT NULL AUTO_INCREMENT PRIMARY KEY':'INTEGER PRIMARY KEY AUTOINCREMENT';
        $suffix=$mysql?' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4':'';
        $tables=[
            'accounts'=>"cid $id, gid INT NOT NULL DEFAULT 0, Email VARCHAR(60) NOT NULL, Password VARCHAR(255) NOT NULL, First_Name VARCHAR(20) NOT NULL, Last_Name VARCHAR(20) NOT NULL, Phone VARCHAR(15) NOT NULL DEFAULT '', Account_Type VARCHAR(20) NOT NULL DEFAULT 'user', Status VARCHAR(8) NOT NULL DEFAULT 'inactive', auth_version INT NOT NULL DEFAULT 1",
            'domains'=>"domain_id $id, domain VARCHAR(253) NOT NULL, owner_id INT NOT NULL DEFAULT 0, group_owner_id INT NOT NULL DEFAULT 0, status VARCHAR(8) NOT NULL DEFAULT 'inactive'",
            'records'=>"record_id $id, domain_id INT NOT NULL, host VARCHAR(512) NOT NULL, type CHAR(1) NOT NULL, val VARCHAR(2000) NOT NULL, distance INT NOT NULL DEFAULT 0, weight INT, port INT, ttl INT NOT NULL DEFAULT 3600",
            'default_records'=>"record_id $id, group_owner_id INT NOT NULL DEFAULT 0, host VARCHAR(512) NOT NULL, type CHAR(1) NOT NULL, val VARCHAR(2000) NOT NULL, distance INT NOT NULL DEFAULT 0, weight INT, port INT, ttl INT NOT NULL DEFAULT 3600, default_type VARCHAR(8) NOT NULL DEFAULT 'group'",
            'log'=>'domain_id INT NOT NULL, cid INT NOT NULL, Email VARCHAR(60) NOT NULL, Name VARCHAR(60) NOT NULL, entry VARCHAR(200) NOT NULL, time BIGINT NOT NULL',
            'web_sessions'=>'id VARCHAR(128) PRIMARY KEY, access BIGINT NOT NULL, data TEXT NOT NULL',
            'password_resets'=>'token_hash VARCHAR(64) PRIMARY KEY, cid INT NOT NULL, expires BIGINT NOT NULL',
            'auth_limits'=>'bucket VARCHAR(64) PRIMARY KEY, started BIGINT NOT NULL, hits INT NOT NULL',
        ];
        foreach($tables as $table=>$definition) $db->run("CREATE TABLE IF NOT EXISTS $table ($definition)$suffix");
        if($mysql) {
            foreach(array_keys($tables) as $table) $db->run("ALTER TABLE $table ENGINE=InnoDB, CONVERT TO CHARACTER SET utf8mb4");
            if(!$db->one('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?',['accounts','auth_version'])) $db->run('ALTER TABLE accounts ADD COLUMN auth_version INT NOT NULL DEFAULT 1');
            $db->run('ALTER TABLE accounts MODIFY Password VARCHAR(255) NOT NULL');
            $db->run('ALTER TABLE domains MODIFY domain VARCHAR(253) NOT NULL');
            foreach(['records','default_records'] as $table) {
                foreach(['weight','port'] as $column) if(!$db->one('SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?',[$table,$column])) $db->run("ALTER TABLE $table ADD COLUMN $column INT NULL");
                $db->run("ALTER TABLE $table MODIFY host VARCHAR(512) NOT NULL, MODIFY val VARCHAR(2000) NOT NULL");
            }
            $db->run('ALTER TABLE web_sessions MODIFY id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL');
        }
        foreach(['accounts'=>'Email','domains'=>'domain'] as $table=>$column) {
            if($db->one("SELECT LOWER($column) AS duplicate FROM $table GROUP BY LOWER($column) HAVING COUNT(*)>1")) throw new \RuntimeException('Resolve duplicate accounts/zones before migration');
            $db->run("UPDATE $table SET $column=LOWER($column)");
            $index='security_unique_'.$table;
            if($mysql) { if(!$db->one('SELECT INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND INDEX_NAME=?',[$table,$index])) $db->run("CREATE UNIQUE INDEX $index ON $table ($column)"); }
            else $db->run("CREATE UNIQUE INDEX IF NOT EXISTS $index ON $table ($column)");
        }
        $db->run('UPDATE accounts SET gid=0 WHERE gid IS NULL');
        $db->run('UPDATE domains SET owner_id=0 WHERE owner_id IS NULL');
        $db->run('UPDATE domains SET group_owner_id=0 WHERE group_owner_id IS NULL');
        $db->run("UPDATE default_records SET group_owner_id=0 WHERE default_type='system'");
        $db->run('UPDATE accounts SET auth_version=auth_version+1');
        $db->run('DELETE FROM web_sessions'); $db->run('DELETE FROM password_resets');
        $db->run('UPDATE accounts SET Status=? WHERE Email=? AND Password=?',['inactive','test@test.com',md5('test')]);
        Security::audit('schema_migrated');
    }
}
