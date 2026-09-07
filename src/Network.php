<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Network
{
    public function __construct(private array $config) {}
    public function destination(string $requested): string {
        // Operators configure IPs, never DNS suffixes. Resolve once and pin the address.
        $addresses = filter_var($requested,FILTER_VALIDATE_IP) ? [$requested] : (gethostbynamel(DNS::name($requested,false)) ?: []);
        if (!$addresses) throw new HttpError(400,'Unknown DNS server.');
        foreach($addresses as $ip) if(!in_array($ip,$this->config['dns_servers'],true)) throw new HttpError(403,'DNS server is not approved.');
        return $addresses[0];
    }
    public function query(string $name,string $type,string $server): string {
        $name=DNS::name($name,false); Security::choice($type,['A','AAAA','NS','MX','PTR','TXT','CNAME','SOA','SRV']);
        return $this->run([$this->config['tools'].'/dnsq',$type,$name,$this->destination($server)]);
    }
    public function transfer(string $zone,string $server): array {
        $zone=DNS::name($zone,false); $ip=$this->destination($server);
        $dir=$this->config['transfer_dir'].'/'.bin2hex(random_bytes(16));
        if(!mkdir($dir,0700)) throw new \RuntimeException('Temporary directory unavailable');
        $file=$dir.'/data';
        try {
            $this->run([$this->config['tools'].'/tcpclient','-R','-T','15',$ip,'53',$this->config['tools'].'/axfr-get',$zone,$file,$file.'.tmp'],[$file,$file.'.tmp']);
            if(!is_file($file) || filesize($file)>5242880) throw new HttpError(400,'Transfer is missing or too large.');
            return DNS::import(file_get_contents($file),$zone);
        } finally {
            foreach([$file,$file.'.tmp'] as $p) if(is_file($p)) unlink($p);
            rmdir($dir);
        }
    }
    private function run(array $args,array $files=[]): string {
        if(!is_file($args[0]) || !is_executable($args[0])) throw new HttpError(503,'DNS tools are unavailable.');
        $process=proc_open($args,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,null,['bypass_shell'=>true]);
        if(!is_resource($process)) throw new \RuntimeException('Cannot start DNS process');
        fclose($pipes[0]); stream_set_blocking($pipes[1],false); stream_set_blocking($pipes[2],false);
        $out=''; $error=''; $deadline=microtime(true)+20; $status=null;
        try {
            do {
                $out.=stream_get_contents($pipes[1]); $error.=stream_get_contents($pipes[2]);
                $large=false; foreach($files as $f) { clearstatcache(true,$f); if(is_file($f) && filesize($f)>5242880) $large=true; }
                if(microtime(true)>$deadline || strlen($out)+strlen($error)>5242880 || $large) { proc_terminate($process,9); throw new HttpError(504,'DNS operation exceeded its limit.'); }
                $status=proc_get_status($process); if($status['running']) usleep(10000);
            } while($status['running']);
            $out.=stream_get_contents($pipes[1]);
            $error.=stream_get_contents($pipes[2]);
            if(strlen($out)+strlen($error)>5242880) throw new HttpError(504,'DNS operation exceeded its limit.');
            if($status['exitcode']!==0) throw new HttpError(400,'DNS operation failed. Check the server and transfer permissions.');
            return $out;
        } finally { fclose($pipes[1]); fclose($pipes[2]); proc_close($process); }
    }
}
