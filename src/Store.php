<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Store
{
    public function __construct(public readonly DB $db) {}
    public static function senior(array $u): bool { return $u['Account_Type'] === 'senior_admin'; }
    public static function admin(array $u): void { if (!in_array($u['Account_Type'], ['senior_admin','group_admin'], true)) throw new HttpError(403,'Administrator access required.'); }
    public static function owns(array $u, array $d): bool {
        return self::senior($u) || (int)$u['cid'] === (int)$d['owner_id'] || ($u['Account_Type']==='group_admin' && (int)$u['cid']===(int)$d['group_owner_id']);
    }
    public function domain(array $u, int $id): array {
        $d=$this->db->one('SELECT * FROM domains WHERE domain_id=?',[$id]);
        if (!$d || !self::owns($u,$d)) throw new HttpError(404,'Domain not found.'); return $d;
    }
    public function domains(array $u, array $input): array {
        $sort=Security::text($input,'sortfield','domain');
        $column=['domain'=>'domain','status'=>'status','owner_id'=>'owner_id','group_owner_id'=>'group_owner_id'][Security::choice($sort,['domain','status','owner_id','group_owner_id'])];
        $direction=Security::choice(Security::text($input,'sortway','asc'),['asc','desc']);
        $sql='SELECT * FROM domains WHERE 1=1'; $p=[];
        if (!self::senior($u)) { $sql.=' AND (owner_id=? OR group_owner_id=?)'; $p[]=$u['cid']; $p[]=$u['Account_Type']==='group_admin'?$u['cid']:-1; }
        $search=Security::text($input,'search');
        if($search!=='') { $sql.=' AND domain LIKE ?'; $p[]='%'.str_replace('*','%',$search).'%'; }
        $scope=Security::text($input,'scope');
        if($scope!=='') { Security::choice($scope,array_merge(range('a','z'),['num']));
            if($scope==='num') $sql.=" AND SUBSTR(domain,1,1) IN ('0','1','2','3','4','5','6','7','8','9')";
            else { $sql.=' AND domain LIKE ?'; $p[]=$scope.'%'; }
        }
        return $this->db->all($sql." ORDER BY $column $direction, domain_id",$p);
    }
    public function defaults(array $u): array {
        self::admin($u); return $this->defaultRows(self::senior($u)?0:(int)$u['cid']);
    }
    private function defaultRows(int $group): array {
        return $group===0 ? $this->db->all("SELECT * FROM default_records WHERE default_type='system' ORDER BY record_id") : $this->db->all("SELECT * FROM default_records WHERE default_type='group' AND group_owner_id=? ORDER BY record_id",[$group]);
    }
    public function addDomain(array $u, string $name, ?array $import = null): int {
        $name=DNS::name($name,false);
        if(!str_contains($name,'.')) throw new HttpError(400,'Use a fully qualified zone name.');
        if($import!==null && !self::senior($u)) throw new HttpError(403,'Senior administrator required.');
        return $this->db->transaction(function() use($u,$name,$import) {
            if($this->db->one('SELECT domain_id FROM domains WHERE domain=?',[$name])) throw new HttpError(409,'Domain already exists.');
            $group=self::senior($u)?0:($u['Account_Type']==='group_admin'?(int)$u['cid']:(int)$u['gid']);
            $this->db->run('INSERT INTO domains (domain,owner_id,group_owner_id,status) VALUES (?,?,?,?)',[$name,self::senior($u)?0:$u['cid'],$group,self::senior($u)?'active':'inactive']);
            $id=(int)$this->db->pdo->lastInsertId();
            $rows=$import ?? ($this->defaultRows($group) ?: $this->defaultRows(0));
            foreach($rows as $row) {
                if($import===null) {
                    foreach(['host','val'] as $field) $row[$field]=preg_replace('/(?<![a-z0-9_-])DOMAIN(?![a-z0-9_-])/i',$name,$row[$field]);
                }
                $r=DNS::record($row,$name); $this->assertReverse($this->domain($u,$id),$r); $this->insertRecord($id,$r);
            }
            $this->log($u,$id,'Domain created'); return $id;
        });
    }
    public function records(array $u, int $domainId, array $input = []): array {
        $this->domain($u,$domainId);
        $column=Security::choice(Security::text($input,'sortfield','type'),['type','host','val','distance','ttl','record_id']);
        $direction=Security::choice(Security::text($input,'sortway','asc'),['asc','desc']);
        return $this->db->all("SELECT * FROM records WHERE domain_id=? AND host LIKE ? ORDER BY $column $direction, record_id",[$domainId,'%'.str_replace('*','%',Security::text($input,'search')).'%']);
    }
    public function record(array $u,int $domainId,int $recordId): array {
        $this->domain($u,$domainId);
        return $this->db->one('SELECT * FROM records WHERE domain_id=? AND record_id=?',[$domainId,$recordId]) ?? throw new HttpError(404,'Record not found.');
    }
    private function insertRecord(int $domainId,array $r): void {
        $this->db->run('INSERT INTO records (domain_id,host,type,val,distance,weight,port,ttl) VALUES (?,?,?,?,?,?,?,?)',[$domainId,$r['host'],$r['type'],$r['val'],$r['distance'],$r['weight'],$r['port'],$r['ttl']]);
    }
    public function saveRecord(array $u,int $domainId,?int $id,array $row): void {
        $d=$this->domain($u,$domainId); $r=DNS::record($row,$d['domain']); $this->assertReverse($d,$r);
        if($id!==null) { $old=$this->record($u,$domainId,$id); if($old['type']!==$r['type']) throw new HttpError(400,'Delete and add a record to change its type.'); }
        if($r['type']==='S' && $this->db->one("SELECT record_id FROM records WHERE domain_id=? AND type='S' AND record_id<>?",[$domainId,$id??0])) throw new HttpError(409,'This domain already has an SOA.');
        if($id===null) $this->insertRecord($domainId,$r);
        else $this->db->run('UPDATE records SET host=?,val=?,distance=?,weight=?,port=?,ttl=? WHERE record_id=? AND domain_id=?',[$r['host'],$r['val'],$r['distance'],$r['weight'],$r['port'],$r['ttl'],$id,$domainId]);
        $this->log($u,$domainId,'Record saved');
    }
    public function deleteRecord(array $u,int $domainId,int $id): void {
        $r=$this->record($u,$domainId,$id);
        if($r['type']==='S') throw new HttpError(400,'Edit the SOA instead of deleting it.');
        if($this->db->run("DELETE FROM records WHERE domain_id=? AND record_id=? AND type<>'S'",[$domainId,$id])->rowCount()!==1) throw new HttpError(409,'Record was already removed.');
        $this->log($u,$domainId,'Record deleted');
    }
    public function saveDefault(array $u,?int $id,array $row): void {
        self::admin($u); $group=self::senior($u)?0:(int)$u['cid'];
        $r=DNS::record($row,'domain');
        if($id!==null && !in_array($id,array_map(fn($r)=>(int)$r['record_id'],$this->defaults($u)),true)) throw new HttpError(404,'Default record not found.');
        if($r['type']==='S') foreach($this->defaults($u) as $old) if($old['type']==='S' && (int)$old['record_id']!==$id) throw new HttpError(409,'Default SOA already exists.');
        $p=[$group,$r['host'],$r['type'],$r['val'],$r['distance'],$r['weight'],$r['port'],$r['ttl'],$group===0?'system':'group'];
        if($id===null) $this->db->run('INSERT INTO default_records (group_owner_id,host,type,val,distance,weight,port,ttl,default_type) VALUES (?,?,?,?,?,?,?,?,?)',$p);
        else { $p[]=$id; $p[]=$group; $this->db->run('UPDATE default_records SET group_owner_id=?,host=?,type=?,val=?,distance=?,weight=?,port=?,ttl=?,default_type=? WHERE record_id=? AND group_owner_id=?',$p); }
    }
    public function deleteDefault(array $u,int $id): void {
        self::admin($u); $group=self::senior($u)?0:(int)$u['cid'];
        if($this->db->run('DELETE FROM default_records WHERE record_id=? AND group_owner_id=? AND default_type=?',[$id,$group,$group===0?'system':'group'])->rowCount()!==1) throw new HttpError(404,'Default record not found.');
    }
    public function deleteDomain(array $u,int $id): void {
        $this->domain($u,$id);
        $this->db->transaction(function() use($id) {
            $this->db->run('DELETE FROM records WHERE domain_id=?',[$id]); $this->db->run('DELETE FROM log WHERE domain_id=?',[$id]); $this->db->run('DELETE FROM domains WHERE domain_id=?',[$id]);
        }); Security::audit('domain_deleted',(int)$u['cid']);
    }
    public function status(array $u,int $id,string $status): void {
        if(!self::senior($u)) throw new HttpError(403,'Senior administrator required.');
        $this->domain($u,$id); Security::choice($status,['active','inactive']);
        $this->db->run('UPDATE domains SET status=? WHERE domain_id=?',[$status,$id]); $this->log($u,$id,'Domain status changed');
    }
    public function account(array $u,int $id): array {
        $a=$this->db->one('SELECT * FROM accounts WHERE cid=?',[$id]);
        if(!$a || (!self::senior($u) && (int)$u['cid']!==$id && !($u['Account_Type']==='group_admin' && (int)$a['gid']===(int)$u['cid'] && $a['Account_Type']==='user'))) throw new HttpError(404,'Account not found.');
        return $a;
    }
    public function accounts(array $u): array {
        self::admin($u); return self::senior($u)?$this->db->all('SELECT cid,Email,First_Name,Last_Name,Account_Type,Status,gid FROM accounts ORDER BY Last_Name, cid'):$this->db->all('SELECT cid,Email,First_Name,Last_Name,Account_Type,Status,gid FROM accounts WHERE gid=? AND Account_Type=? ORDER BY Last_Name, cid',[$u['cid'],'user']);
    }
    public function saveAccount(array $u,?int $id,array $in): void {
        if($id===null) self::admin($u);
        $old=$id===null?null:$this->account($u,$id);
        $email=Security::email(Security::text($in,'email_address'));
        $first=trim(Security::text($in,'first_name')); $last=trim(Security::text($in,'last_name')); $phone=Security::text($in,'phone');
        if($first==='' || $last==='' || strlen($first)>20 || strlen($last)>20 || strlen($phone)>15) throw new HttpError(400,'Names are required (20 bytes each); phone is limited to 15 bytes.');
        $pass=Security::text($in,'password'); if($pass!==Security::text($in,'password2')) throw new HttpError(400,'Passwords do not match.');
        $hash=$pass!==''?Security::password($pass):($old['Password']??throw new HttpError(400,'Password required.'));
        $role=self::senior($u)?Security::choice(Security::text($in,'account_type','user'),['user','group_admin','senior_admin']):($old['Account_Type']??'user');
        $status=self::senior($u)?Security::choice(Security::text($in,'status','active'),['active','inactive']):($old['Status']??'active');
        $group=self::senior($u)?Security::integer($in['gid']??'0'):($old['gid']??$u['cid']);
        if($group!==0 && !$this->db->one("SELECT cid FROM accounts WHERE cid=? AND Account_Type='group_admin'",[$group])) throw new HttpError(400,'Invalid group owner.');
        if($id===(int)$u['cid'] && ($role!==$u['Account_Type'] || $status!=='active' || (int)$group!==(int)$u['gid'])) throw new HttpError(400,'Another senior administrator must change your role, status or group.');
        $this->db->transaction(function() use($u,$old,$id,$first,$last,$phone,$email,$hash,$role,$status,$group) {
            if($this->db->one('SELECT cid FROM accounts WHERE Email=? AND cid<>?',[$email,$id??0])) throw new HttpError(409,'Email is already registered.');
            $p=[$first,$last,$phone,$email,$hash,$role,$status,$group];
            if($id===null) $this->db->run('INSERT INTO accounts (First_Name,Last_Name,Phone,Email,Password,Account_Type,Status,gid,auth_version) VALUES (?,?,?,?,?,?,?,?,1)',$p);
            else {
                $invalidate=$old['Password']!==$hash || $old['Email']!==$email || $old['Account_Type']!==$role || $old['Status']!==$status || (int)$old['gid']!==(int)$group;
                $p[]=$invalidate?1:0; $p[]=$id;
                $this->db->run('UPDATE accounts SET First_Name=?,Last_Name=?,Phone=?,Email=?,Password=?,Account_Type=?,Status=?,gid=?,auth_version=auth_version+? WHERE cid=?',$p);
                if($invalidate) $this->db->run('DELETE FROM password_resets WHERE cid=?',[$id]);
            }
        }); Security::audit('account_saved',(int)$u['cid']);
    }
    public function deleteAccount(array $u,int $id): void {
        self::admin($u); $this->account($u,$id);
        if($id===(int)$u['cid']) throw new HttpError(400,'Cannot delete your own account.');
        $this->db->transaction(function() use($u,$id) {
            // Remove dangling group memberships as well as direct ownership.
            $this->db->run('UPDATE domains SET owner_id=? WHERE owner_id=?',[self::senior($u)?0:$u['cid'],$id]);
            $this->db->run('UPDATE domains SET group_owner_id=0 WHERE group_owner_id=?',[$id]);
            $this->db->run('UPDATE accounts SET gid=0, auth_version=auth_version+1 WHERE gid=?',[$id]);
            $this->db->run('DELETE FROM default_records WHERE group_owner_id=?',[$id]);
            $this->db->run('DELETE FROM password_resets WHERE cid=?',[$id]);
            if($this->db->run('DELETE FROM accounts WHERE cid=?',[$id])->rowCount()!==1) throw new HttpError(409,'Account was already removed.');
        }); Security::audit('account_deleted',(int)$u['cid']);
    }
    public function changeOwner(array $u,int $id,int $owner,int $group): void {
        self::admin($u); $d=$this->domain($u,$id);
        if($owner!==0) $this->account($u,$owner); elseif(!self::senior($u)) throw new HttpError(403,'Invalid owner.');
        if(!self::senior($u)) $group=(int)$d['group_owner_id'];
        if($group!==0 && !$this->db->one("SELECT cid FROM accounts WHERE cid=? AND Account_Type='group_admin'",[$group])) throw new HttpError(400,'Invalid group.');
        $this->db->run('UPDATE domains SET owner_id=?,group_owner_id=? WHERE domain_id=?',[$owner,$group,$id]); $this->log($u,$id,'Ownership changed');
    }
    public function log(array $u,int $domain,string $entry): void {
        $this->db->run('INSERT INTO log (domain_id,cid,Email,Name,entry,time) VALUES (?,?,?,?,?,?)',[$domain,$u['cid'],$u['Email'],$u['First_Name'].' '.$u['Last_Name'],$entry,time()]);
    }
    public function assertReverse(array $domain,array $r): void {
        if(!in_array($r['type'],['=','6'],true)) return;
        $reverse=DNS::reverse($r['val']); $best=null;
        foreach($this->db->all("SELECT * FROM domains WHERE status='active'") as $d) if(DNS::inside($reverse,$d['domain']) && (!$best || strlen($d['domain'])>strlen($best['domain']))) $best=$d;
        if(!$best || (int)$best['owner_id']!==(int)$domain['owner_id'] || (int)$best['group_owner_id']!==(int)$domain['group_owner_id']) throw new HttpError(400,'Automatic PTR requires an active reverse zone with identical ownership.');
    }
    public function export(): string {
        return $this->db->transaction(function() {
            $out='';
            foreach($this->db->all("SELECT * FROM domains WHERE status='active' ORDER BY domain") as $d) {
                $zone=DNS::name($d['domain'],false); $rows=$this->db->all('SELECT * FROM records WHERE domain_id=? ORDER BY type,host,record_id',[$d['domain_id']]);
                if(count(array_filter($rows,fn($r)=>$r['type']==='S'))!==1) throw new HttpError(409,'Export rejected: an active zone requires exactly one SOA.');
                $out.="\n#$zone\n";
                foreach($rows as $r) { $this->assertReverse($d,$r); $out.=DNS::export($r,$zone); }
            }
            return $out;
        });
    }
}
