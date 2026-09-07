<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class DNS
{
    public const TYPES = ['A'=>'A', 'A+PTR'=>'=', 'AAAA'=>'3', 'AAAA+PTR'=>'6', 'NS'=>'N', 'MX'=>'M', 'PTR'=>'P', 'TXT'=>'T', 'CNAME'=>'C', 'SOA'=>'S', 'SRV'=>'V', 'SPF'=>'F'];
    public static function name(string $name, bool $owner = true): string {
        $name = strtolower(str_ends_with($name, '.') ? substr($name, 0, -1) : $name);
        if ($name === '' || strlen($name) > 253) throw new HttpError(400, 'Invalid DNS name.');
        foreach (explode('.', $name) as $i => $label) {
            if ($owner && $i === 0 && $label === '*') continue;
            $pattern = $owner ? '/\A[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\z/' : '/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/';
            if (!preg_match($pattern, $label)) throw new HttpError(400, 'Invalid DNS name.');
        }
        return $name;
    }
    public static function inside(string $name, string $zone): bool { return $name === $zone || str_ends_with($name, '.'.$zone); }
    public static function owner(string $name, string $zone): string {
        $zone = self::name($zone, false);
        if ($name === '' || $name === '@') return $zone;
        $absolute = str_ends_with($name, '.'); $name = self::name($name);
        if (!self::inside($name, $zone) && !$absolute) $name = self::name($name.'.'.$zone);
        if (!self::inside($name, $zone)) throw new HttpError(400, 'Record owner is outside the authorized zone.');
        return $name;
    }
    public static function reverse(string $ip): string {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return implode('.', array_reverse(explode('.', $ip))).'.in-addr.arpa';
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) throw new HttpError(400, 'Invalid IP address.');
        return implode('.', array_reverse(str_split(bin2hex(inet_pton($ip))))).'.ip6.arpa';
    }
    public static function record(array $row, string $zone): array {
        $type = Security::choice((string)($row['type'] ?? ''), array_values(self::TYPES));
        $r = ['type'=>$type, 'host'=>(string)($row['host'] ?? ''), 'val'=>(string)($row['val'] ?? ''),
              'ttl'=>Security::integer($row['ttl'] ?? 3600), 'distance'=>0, 'weight'=>null, 'port'=>null];
        if ($type === 'S') {
            $host = explode(':', $r['host']); $timers = explode(':', $r['val']);
            if (count($host) !== 2 || count($timers) < 4 || count($timers) > 5) throw new HttpError(400, 'Invalid SOA fields.');
            $r['host'] = self::name($host[0]).':'.self::name($host[1], false);
            $serial = $timers[4] ?? '';
            $r['val'] = implode(':', array_map(fn($v) => Security::integer($v), array_slice($timers, 0, 4))).':'.($serial === '' ? '' : Security::integer($serial, 0, 4294967295));
            return $r;
        }
        // Stored data must already be absolute and in-zone; never repair at export.
        $r['host'] = self::name($r['host']);
        if (!self::inside($r['host'], self::name($zone, false))) throw new HttpError(400, 'Record owner is outside the authorized zone.');
        if (in_array($type, ['A','='], true)) {
            if (!filter_var($r['val'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) throw new HttpError(400, 'Invalid IPv4 address.');
        } elseif (in_array($type, ['3','6'], true)) {
            if (!filter_var($r['val'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) throw new HttpError(400, 'Invalid IPv6 address.');
            $r['val'] = inet_ntop(inet_pton($r['val']));
        } elseif (in_array($type, ['N','M','P','C','V'], true)) {
            $r['val'] = self::name($r['val'], false);
            if ($type === 'P' && !str_ends_with($r['host'], '.in-addr.arpa') && !str_ends_with($r['host'], '.ip6.arpa')) throw new HttpError(400, 'PTR must belong to a reverse zone.');
        } else {
            if (strlen($r['val']) > 2000) throw new HttpError(400, 'TXT/SPF values are limited to 2000 bytes.');
        }
        if (in_array($type, ['M','V'], true)) $r['distance'] = Security::integer($row['distance'] ?? 0, 0, 65535);
        if ($type === 'V') {
            if (!preg_match('/\A_[a-z0-9-]+\._[a-z0-9-]+\./', $r['host'])) throw new HttpError(400, 'SRV owner must start with _service._protocol.');
            $r['weight'] = Security::integer($row['weight'] ?? 0, 0, 65535);
            $r['port'] = Security::integer($row['port'] ?? 0, 0, 65535);
        }
        return $r;
    }
    public static function fromForm(array $input, string $zone): array {
        $type = Security::choice(Security::text($input, 'type'), array_keys(self::TYPES));
        $r = ['type'=>self::TYPES[$type], 'host'=>Security::text($input, 'name'), 'val'=>Security::text($input, 'address')];
        foreach (['ttl','distance','weight','port'] as $key) $r[$key] = Security::text($input, $key, $key === 'ttl' ? '3600' : '0');
        if ($type === 'SOA') {
            $r['host'] = Security::text($input, 'contactaddr').':'.Security::text($input, 'primary_name_server');
            $r['val'] = implode(':', array_map(fn($k)=>Security::text($input, $k), ['refresh','retry','expire','minimum','serial']));
        } else { $r['host'] = self::owner($r['host'], $zone); }
        return self::record($r, $zone);
    }
    public static function octal(string $bytes): string {
        $out = ''; foreach (str_split($bytes) as $byte) $out .= sprintf('\\%03o', ord($byte)); return $out;
    }
    public static function wireName(string $name): string {
        $out = ''; foreach (explode('.', self::name($name, false)) as $label) $out .= chr(strlen($label)).$label; return $out."\0";
    }
    public static function export(array $row, string $zone): string {
        $zone = self::name($zone, false);
        $r = self::record($row, $zone); $h=$r['host']; $v=$r['val']; $ttl=$r['ttl']; $d=$r['distance'];
        $line = match ($r['type']) {
            'A' => "+$h:$v:$ttl\n", '=' => "=$h:$v:$ttl\n",
            'N' => "&$h::$v:$ttl\n", 'M' => "@$h::$v:$d:$ttl\n",
            'P' => "^$h:$v:$ttl\n", 'C' => "C$h:$v:$ttl\n",
            'T' => "'$h:".self::octal($v).":$ttl\n",
            'F' => ":$h:99:".self::octal(implode('', array_map(fn($c) => chr(strlen($c)).$c, str_split($v, 255)))).":$ttl\n",
            'V' => ":$h:33:".self::octal(pack('nnn', $d, $r['weight'], $r['port']).self::wireName($v)).":$ttl\n",
            '3','6' => ":$h:28:".self::octal(inet_pton($v)).":$ttl\n",
            'S' => self::soaLine($r, $zone),
        };
        if ($r['type'] === '6') $line .= '^'.self::reverse($v).":$h:$ttl\n";
        return $line;
    }
    private static function soaLine(array $r, string $zone): string {
        [$email,$ns] = explode(':',$r['host']); [$refresh,$retry,$expire,$min,$serial] = explode(':',$r['val']);
        return "Z$zone:$ns:$email:$serial:$refresh:$retry:$expire:$min:{$r['ttl']}\n";
    }
    public static function decode(string $s): string {
        if (preg_match('/\\\\(?![0-3][0-7]{2})/', $s)) throw new HttpError(400, 'Invalid transfer escaping.');
        return preg_replace_callback('/\\\\([0-3][0-7]{2})/', fn($m)=>chr(octdec($m[1])), $s);
    }
    public static function import(string $data, string $zone): array {
        $records = [];
        foreach (explode("\n", $data) as $line) {
            if ($line === '' || $line[0] === '#') continue;
            $p = explode(':', substr($line,1)); $type=$line[0];
            $r = ['host'=>self::decode($p[0]), 'ttl'=>3600, 'distance'=>0];
            if (in_array($type, ['+','=','C','^',"'"], true)) {
                $r += ['type'=>['+'=>'A','='=>'=','C'=>'C','^'=>'P',"'"=>'T'][$type], 'val'=>self::decode($p[1] ?? '')];
                $r['ttl']=$p[2] ?? 3600;
            } elseif (in_array($type, ['@','&'], true)) {
                $r['type']=$type === '@' ? 'M' : 'N'; $r['val']=self::decode($p[2] ?? '');
                if (($p[1] ?? '') !== '') throw new HttpError(400, 'Import glue addresses as separate A records.');
                $r['distance']=$type === '@' ? ($p[3] ?? '0') : 0; $r['ttl']=$p[$type === '@' ? 4 : 3] ?? 3600;
            } elseif ($type === 'Z') {
                if (self::name($p[0],false) !== $zone) throw new HttpError(400, 'SOA is outside the imported zone.');
                $r['type']='S'; $r['host']=($p[2]??'').':'.($p[1]??'');
                $r['val']=implode(':', [$p[4]??'16384',$p[5]??'2048',$p[6]??'1048576',$p[7]??'2560',$p[3]??'']); $r['ttl']=$p[8]??3600;
            } elseif ($type === ':') {
                $wire=self::decode($p[2]??''); $rr=Security::integer($p[1]??'',1,65535); $r['ttl']=$p[3]??3600;
                if ($rr === 28 && strlen($wire) === 16) { $r['type']='3'; $r['val']=inet_ntop($wire); }
                elseif (in_array($rr,[16,99],true)) {
                    $r['type']=$rr===16?'T':'F'; $r['val']='';
                    for($i=0;$i<strlen($wire);) { $len=ord($wire[$i++]); if($i+$len>strlen($wire)) throw new HttpError(400,'Invalid TXT wire data.'); $r['val'].=substr($wire,$i,$len); $i+=$len; }
                } elseif ($rr === 33 && strlen($wire) >= 7) {
                    $r['type']='V'; $r+=unpack('ndistance/nweight/nport',substr($wire,0,6));
                    $r['distance']=unpack('n',substr($wire,0,2))[1]; $labels=[]; $i=6;
                    while($i<strlen($wire) && ($len=ord($wire[$i++]))!==0) { if($len>63 || $i+$len>strlen($wire)) throw new HttpError(400,'Invalid SRV wire data.'); $labels[]=substr($wire,$i,$len); $i+=$len; }
                    if($i!==strlen($wire) || $wire[$i-1]!=="\0") throw new HttpError(400,'Invalid SRV terminator.');
                    $r['val']=implode('.',$labels);
                } else throw new HttpError(400,'Unsupported transfer record type.');
            } else throw new HttpError(400,'Unsupported transfer record format.');
            $records[]=self::record($r,$zone);
        }
        if (count(array_filter($records,fn($r)=>$r['type']==='S'))!==1) throw new HttpError(400,'Transfer must contain exactly one SOA.');
        return $records;
    }
}
