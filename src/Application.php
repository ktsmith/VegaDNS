<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Application
{
    private Auth $auth;
    private Store $store;
    private Network $network;
    public function __construct(private DB $db, private array $config) {
        $this->auth=new Auth($db,$config); $this->store=new Store($db); $this->network=new Network($config);
    }
    private function redirect(array $p): never { header('Location: '.Security::url($p),true,303); exit; }
    public function run(): void {
        $method=$_SERVER['REQUEST_METHOD']??'GET';
        if(!in_array($method,['GET','POST'],true)) throw new HttpError(405,'Unsupported HTTP method.');
        // Never read cookies through $_REQUEST, and never merge action selectors across methods.
        $in=$method==='POST'?$_POST:$_GET;
        foreach(['VDNSSessid','password','password2'] as $key) if(isset($_GET[$key])) throw new HttpError(400,'Credentials are not accepted in URLs.');
        if(isset($_POST['VDNSSessid'])) throw new HttpError(400,'URL/form session IDs are not accepted.');
        $state=Security::text($in,'state','login_screen');
        if($state==='get_data') { $this->export($method); return; }
        Security::startSession($this->config,$this->db);
        if($method==='POST') {
            Security::requirePost($method,$in);
            Security::requireOrigin($_SERVER['HTTP_ORIGIN']??null,$this->config['base_url']);
        }
        if($state==='login') {
            Security::requirePost($method,$in);
            if($this->auth->login(Security::text($in,'email'),Security::text($in,'password'),$_SERVER['REMOTE_ADDR']??'')) $this->redirect(['state'=>'logged_in','mode'=>'domains']);
            echo View::page('Sign in',array_merge(['Unable to sign in. Check your credentials or try again later.'],$this->loginForm())); return;
        }
        if($state==='help' || $state==='reset') { $this->help($in,$method,$state); return; }
        if($state==='end') {
            Security::requirePost($method,$in); $_SESSION=[]; session_destroy();
            setcookie(session_name(),'', ['expires'=>time()-3600,'path'=>$this->config['cookie_path'],'secure'=>true,'httponly'=>true,'samesite'=>'Lax']);
            $this->redirect(['state'=>'login_screen']);
        }
        $u=$this->auth->current();
        if(!$u) { Security::clearIdentity(); echo View::page('Sign in',$this->loginForm()); return; }
        $mode=Security::text($in,'mode','domains');
        match($mode) {
            'domains','main_menu' => $this->domains($u,$in,$method),
            'records' => $this->records($u,$in,$method,false),
            'default_records' => $this->records($u,$in,$method,true),
            'users' => $this->users($u,$in,$method),
            'dnsquery' => $this->query($u,$in,$method),
            default => throw new HttpError(404,'Unknown page.'),
        };
    }
    private function loginForm(): array {
        return [View::form(['state'=>'login'],['email'=>['Email','','email'],'password'=>['Password','','password']],'Sign in'),View::link('Forgot your password?',['state'=>'help'])];
    }
    private function help(array $in,string $method,string $state): void {
        $mode=Security::text($in,'mode'); $content=[];
        if($state==='reset') {
            if($method==='GET' && isset($in['token'])) {
                $token=Security::text($in,'token');
                if(!preg_match('/\A[a-f0-9]{64}\z/',$token)) throw new HttpError(400,'Invalid reset link.');
                $_SESSION['reset_token']=$token; $this->redirect(['state'=>'reset']);
            }
            if($method==='POST') {
                $password=Security::text($in,'password');
                if($password!==Security::text($in,'password2')) throw new HttpError(400,'Passwords do not match.');
                $success=$this->auth->reset($_SESSION['reset_token']??'',$password);
                unset($_SESSION['reset_token']);
                if(!session_regenerate_id(true)) throw new \RuntimeException('Session rotation failed');
                $_SESSION['csrf']=bin2hex(random_bytes(32));
                echo View::page('Password reset',[$success?'Password changed. Sign in again.':'This link is invalid or expired.',View::link('Sign in',['state'=>'login_screen'])]); return;
            }
            $content[]='Choose a password containing 12–72 bytes. The link expires after 30 minutes.';
            $content[]=View::form(['state'=>'reset'],['password'=>['New password','','password'],'password2'=>['Repeat password','','password']],'Set password');
        } else {
            if($mode==='send_pass') {
                Security::requirePost($method,$in);
                $this->auth->requestReset(Security::text($in,'username'),$_SERVER['REMOTE_ADDR']??'',function($to,$url) {
                    if(!mail($to,'VegaDNS password reset',"Use this one-time link within 30 minutes:\n\n$url\n\nIf you did not request this, ignore this email. Your password has not changed.", 'From: '.$this->config['support_email'])) Security::audit('reset_mail_failed');
                });
                $content[]='If the account is active and requests are permitted, a reset link will be sent.';
            }
            $content[]=View::form(['state'=>'help','mode'=>'send_pass'],['username'=>['Account email','','email']],'Send reset link');
        }
        $content[]=View::link('Sign in',['state'=>'login_screen']); echo View::page('Password help',$content);
    }
    private function domainId(array $u,array $in): int {
        if(isset($in['domain_id'])) $id=Security::integer($in['domain_id'],1);
        else {
            $d=$this->db->one('SELECT domain_id FROM domains WHERE domain=?',[DNS::name(Security::text($in,'domain'),false)]);
            $id=$d?(int)$d['domain_id']:0;
        }
        $this->store->domain($u,$id); return $id;
    }
    private function domains(array $u,array $in,string $method): void {
        $action=Security::text($in,'domain_mode'); $base=['state'=>'logged_in','mode'=>'domains'];
        if(in_array($action,['add_now','delete_now','activate_domain','deactivate_domain','change_owner_now','import_domains_now'],true)) {
            Security::requirePost($method,$in);
            if($action==='add_now') {
                $id=$this->store->addDomain($u,Security::text($in,'domain')); $this->redirect(['state'=>'logged_in','mode'=>'records','domain_id'=>$id]);
            } elseif($action==='import_domains_now') {
                if(!Store::senior($u)) throw new HttpError(403,'Senior administrator required.');
                if(!(new Auth($this->db,$this->config))->limit('import',(string)$u['cid'],10,300)) throw new HttpError(429,'Try again later.');
                $names=array_unique(preg_split('/\r?\n/',trim(Security::text($in,'domains'))));
                if(count($names)>10 || $names===['']) throw new HttpError(400,'Import 1–10 zones at a time.');
                // Release the session descriptor before starting tcpclient; no public helper is used.
                session_write_close();
                $transfers=[];
                foreach($names as $name) { $zone=DNS::name(trim($name),false); $transfers[$zone]=$this->network->transfer($zone,Security::text($in,'hostname')); }
                $u=$this->auth->current();
                if(!$u || !Store::senior($u)) throw new HttpError(403,'Administrator session was revoked. Sign in again.');
                foreach(array_keys($transfers) as $zone) if($this->db->one('SELECT domain_id FROM domains WHERE domain=?',[$zone])) throw new HttpError(409,'An imported domain already exists.');
                foreach($transfers as $zone=>$rows) $this->store->addDomain($u,$zone,$rows);
            } else {
                $id=$this->domainId($u,$in);
                match($action) {
                    'delete_now'=>$this->store->deleteDomain($u,$id),
                    'activate_domain'=>$this->store->status($u,$id,'active'),
                    'deactivate_domain'=>$this->store->status($u,$id,'inactive'),
                    'change_owner_now'=>$this->store->changeOwner($u,$id,Security::integer($in['owner_id']??''),Security::integer($in['group_owner_id']??'0')),
                };
            }
            $this->redirect($base);
        }
        if($action==='add') { echo View::page('New domain',[View::form($base+['domain_mode'=>'add_now'],['domain'=>['Domain name','','text']],'Create domain')],$u); return; }
        if($action==='import_domains') {
            if(!Store::senior($u)) throw new HttpError(403,'Senior administrator required.');
            echo View::page('Import zones',[View::form($base+['domain_mode'=>'import_domains_now'],['hostname'=>['Approved DNS server','',$this->config['dns_servers']],'domains'=>['Zones (one per line)','','textarea']],'Import')],$u); return;
        }
        if(in_array($action,['delete','change_owner'],true)) {
            $id=$this->domainId($u,$in); $d=$this->store->domain($u,$id);
            if($action==='delete') $content=["Delete {$d['domain']} and all of its records?",View::form($base+['domain_mode'=>'delete_now','domain_id'=>$id],[],'Delete domain')];
            else {
                Store::admin($u); $choices=array_map(fn($a)=>(string)$a['cid'],$this->store->accounts($u)); $choices[]=(string)$u['cid'];
                if(Store::senior($u)) $choices[]='0';
                $fields=['owner_id'=>['New owner account ID',$d['owner_id'],array_unique($choices)]];
                if(Store::senior($u)) $fields['group_owner_id']=['Group administrator ID (0 for none)',$d['group_owner_id'],'number'];
                $content=[View::form($base+['domain_mode'=>'change_owner_now','domain_id'=>$id],$fields,'Change owner')];
            }
            echo View::page('Domain: '.$d['domain'],$content,$u); return;
        }
        if(!in_array($action,['','delete_cancelled','domain_prefs'],true)) throw new HttpError(404,'Unknown domain action.');
        $rows=[];
        foreach($this->store->domains($u,$in) as $d) {
            $p=$base+['domain_id'=>$d['domain_id']];
            $actions=[View::link('Delete',$p+['domain_mode'=>'delete'])];
            if($u['Account_Type']!=='user') $actions[]=View::link('Owner',$p+['domain_mode'=>'change_owner']);
            if(Store::senior($u)) $actions[]=View::form($p+['domain_mode'=>$d['status']==='active'?'deactivate_domain':'activate_domain'],[],$d['status']==='active'?'Deactivate':'Activate');
            $rows[]=[View::link($d['domain'],['state'=>'logged_in','mode'=>'records','domain_id'=>$d['domain_id']]),$d['status'],$d['owner_id'],$d['group_owner_id'],View::join($actions)];
        }
        echo View::page('Domains',[View::form($base,['search'=>['Search',Security::text($in,'search'),'text']],'Search'),View::table(['Domain','Status','Owner ID','Group ID','Actions'],$rows)],$u);
    }
    private function recordFields(?array $r,string $zone): array {
        $type=$r?array_search($r['type'],DNS::TYPES,true):'A';
        $fields=['name'=>['Name (relative or absolute)', $r['host']??$zone,'text'], 'type'=>['Type',$type,$r?[$type]:array_keys(DNS::TYPES)], 'address'=>['Address / value',$r['val']??'','text'], 'ttl'=>['TTL',$r['ttl']??3600,'number'], 'distance'=>['MX/SRV priority',$r['distance']??0,'number'], 'weight'=>['SRV weight',$r['weight']??0,'number'], 'port'=>['SRV port',$r['port']??0,'number']];
        [$email,$ns]=explode(':',($r && $type==='SOA')?$r['host']:'hostmaster.'.$zone.':ns1.'.$zone);
        $timers=explode(':',($r && $type==='SOA')?$r['val']:'16384:2048:1048576:2560:');
        $fields['contactaddr']=['SOA contact (DNS mailbox form)',$email,'text']; $fields['primary_name_server']=['SOA primary server',$ns,'text'];
        foreach(['refresh','retry','expire','minimum','serial'] as $i=>$key) $fields[$key]=['SOA '.$key,$timers[$i]??'','number'];
        return $fields;
    }
    private function records(array $u,array $in,string $method,bool $defaults): void {
        $action=Security::text($in,'record_mode'); $base=['state'=>'logged_in','mode'=>$defaults?'default_records':'records'];
        if($defaults) { Store::admin($u); $zone='domain'; $domainId=0; $rows=$this->store->defaults($u); }
        else { $domainId=$this->domainId($u,$in); $d=$this->store->domain($u,$domainId); $zone=$d['domain']; $base['domain_id']=$domainId; $rows=$this->store->records($u,$domainId,$in); }
        $id=isset($in['record_id'])?Security::integer($in['record_id'],1):null;
        $selected=null;
        if($id!==null) {
            if($defaults) { foreach($rows as $r) if((int)$r['record_id']===$id) $selected=$r; if(!$selected) throw new HttpError(404,'Default record not found.'); }
            else $selected=$this->store->record($u,$domainId,$id);
        }
        if(in_array($action,['edit_soa','edit_soa_now'],true)) {
            foreach($rows as $r) if($r['type']==='S') { $selected=$r; $id=(int)$r['record_id']; break; }
            $in['type']='SOA';
        }
        if(in_array($action,['add_record_now','edit_record_now','edit_soa_now','delete_now'],true)) {
            Security::requirePost($method,$in);
            if($action==='delete_now') {
                if($id===null) throw new HttpError(400,'Record ID required.');
                if($defaults) $this->store->deleteDefault($u,$id); else $this->store->deleteRecord($u,$domainId,$id);
            } else {
                if($action==='edit_record_now' && $id===null) throw new HttpError(400,'Record ID required.');
                if($action==='add_record_now') $id=null;
                $row=DNS::fromForm($in,$zone);
                if($defaults) $this->store->saveDefault($u,$id,$row); else $this->store->saveRecord($u,$domainId,$id,$row);
            }
            $this->redirect($base);
        }
        if($action==='delete') {
            if(!$selected) throw new HttpError(400,'Record ID required.');
            echo View::page('Delete record',[$selected['host'],View::form($base+['record_mode'=>'delete_now','record_id'=>$id],[],'Delete record')],$u); return;
        }
        if(in_array($action,['add_record','edit_record','edit_soa'],true)) {
            if($action==='edit_record' && !$selected) throw new HttpError(400,'Record ID required.');
            if($action==='edit_soa' && !$selected) $selected=['type'=>'S','host'=>'hostmaster.'.$zone.':ns1.'.$zone,'val'=>'16384:2048:1048576:2560:','ttl'=>3600];
            $params=$base+['record_mode'=>$id!==null?'edit_record_now':'add_record_now']; if($id!==null) $params['record_id']=$id;
            echo View::page('Record for '.$zone,[View::form($params,$this->recordFields($selected,$zone),'Save record')],$u); return;
        }
        if($action==='view_log' && !$defaults) {
            $logs=$this->db->all('SELECT Name,Email,entry,time FROM log WHERE domain_id=? ORDER BY time DESC',[$domainId]);
            echo View::page('Domain log',[View::table(['Name','Email','Event','Timestamp'],array_map('array_values',$logs))],$u); return;
        }
        if(!in_array($action,['','delete_cancelled'],true)) throw new HttpError(404,'Unknown record action.');
        $display=[];
        foreach($rows as $r) $display[]=[$r['host'],array_search($r['type'],DNS::TYPES,true),$r['val'],$r['ttl'],View::join([View::link('Edit',$base+['record_mode'=>'edit_record','record_id'=>$r['record_id']]),View::link('Delete',$base+['record_mode'=>'delete','record_id'=>$r['record_id']])])];
        $content=[View::link('Add record',$base+['record_mode'=>'add_record']),View::link('SOA',$base+['record_mode'=>'edit_soa']),View::table(['Host','Type','Value','TTL','Actions'],$display)];
        if(!$defaults) $content[]=View::link('View log',$base+['record_mode'=>'view_log']);
        else $content[]='Use DOMAIN as a label placeholder. New domains use group defaults when present, otherwise system defaults.';
        echo View::page($defaults?'Default records':'Records: '.$zone,$content,$u);
    }
    private function users(array $u,array $in,string $method): void {
        $action=Security::text($in,'user_mode','show_users'); $base=['state'=>'logged_in','mode'=>'users'];
        $id=isset($in['cid'])?Security::integer($in['cid'],1):(int)$u['cid'];
        if(in_array($action,['edit_account_now','add_account_now','delete_now'],true)) {
            Security::requirePost($method,$in);
            if($action==='delete_now') $this->store->deleteAccount($u,$id);
            else $this->store->saveAccount($u,$action==='add_account_now'?null:$id,$in);
            $this->redirect(['state'=>'logged_in','mode'=>'domains']);
        }
        if($action==='delete') { $a=$this->store->account($u,$id); Store::admin($u); echo View::page('Delete account',[$a['Email'],View::form($base+['cid'=>$id,'user_mode'=>'delete_now'],[],'Delete account')],$u); return; }
        if(in_array($action,['edit_account','add_account'],true)) {
            if($action==='add_account') Store::admin($u);
            $a=$action==='edit_account'?$this->store->account($u,$id):[];
            $fields=['first_name'=>['First name',$a['First_Name']??'','text'],'last_name'=>['Last name',$a['Last_Name']??'','text'],'email_address'=>['Email',$a['Email']??'','email'],'phone'=>['Phone',$a['Phone']??'','text'],'password'=>['New password (blank to keep current)','','password'],'password2'=>['Repeat password','','password']];
            if(Store::senior($u)) $fields+=['account_type'=>['Role',$a['Account_Type']??'user',['user','group_admin','senior_admin']], 'status'=>['Status',$a['Status']??'active',['active','inactive']], 'gid'=>['Group administrator ID (0 for none)',$a['gid']??0,'number']];
            echo View::page('Account',[View::form($base+['cid'=>$id,'user_mode'=>$action.'_now'],$fields,'Save account')],$u); return;
        }
        if(!in_array($action,['show_users','cancelled'],true)) throw new HttpError(404,'Unknown account action.');
        $rows=[];
        foreach($this->store->accounts($u) as $a) $rows[]=[$a['cid'],$a['First_Name'].' '.$a['Last_Name'],$a['Email'],$a['Account_Type'],$a['Status'],$a['gid'],View::join([View::link('Edit',$base+['cid'=>$a['cid'],'user_mode'=>'edit_account']),View::link('Delete',$base+['cid'=>$a['cid'],'user_mode'=>'delete'])])];
        echo View::page('Accounts',[View::link('Add account',$base+['user_mode'=>'add_account']),View::table(['ID','Name','Email','Role','Status','Group','Actions'],$rows)],$u);
    }
    private function query(array $u,array $in,string $method): void {
        $content=[];
        if(isset($in['query_mode'])) {
            Security::requirePost($method,$in);
            if(!$this->auth->limit('dns-query',(string)$u['cid'],30,300)) throw new HttpError(429,'Try again later.');
            session_write_close();
            $content[]=new Html('<pre>'.Security::encode($this->network->query(Security::text($in,'name'),Security::text($in,'type'),Security::text($in,'host'))).'</pre>');
        }
        $content[]=View::form(['state'=>'logged_in','mode'=>'dnsquery','query_mode'=>'do_query'],['name'=>['Name','','text'],'type'=>['Type','A',['A','AAAA','NS','MX','PTR','TXT','CNAME','SOA','SRV']],'host'=>['Approved DNS server','',$this->config['dns_servers']]],'Query');
        echo View::page('DNS query',$content,$u);
    }
    private function export(string $method): void {
        if($method!=='GET') throw new HttpError(405,'Export requires GET.');
        $token=$this->config['export_token'];
        $authorization=$_SERVER['HTTP_AUTHORIZATION']??'';
        if(strlen($token)<32 || !hash_equals('Bearer '.$token,$authorization)) throw new HttpError(403,'Export access denied.');
        $data=$this->store->export(); // Validate everything before emitting even one byte.
        header('Content-Type: text/plain; charset=UTF-8'); echo $data;
    }
}
