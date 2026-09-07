<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Html { public function __construct(public readonly string $value) {} }
final class View
{
    public static function link(string $label,array $params): Html { return new Html('<a href="'.Security::encode(Security::url($params)).'">'.Security::encode($label).'</a>'); }
    public static function join(array $parts): Html { return new Html(implode(' ',array_map(fn($p)=>$p instanceof Html?$p->value:Security::encode($p),$parts))); }
    public static function form(array $params,array $fields,string $button): Html {
        $out='<form method="post" action="index.php">'; $params['csrf']=Security::csrf();
        foreach($params as $key=>$value) $out.='<input type="hidden" name="'.Security::encode($key).'" value="'.Security::encode($value).'">';
        foreach($fields as $key=>$field) {
            [$label,$value,$type]=$field+['','', 'text'];
            $out.='<label>'.Security::encode($label).' ';
            if(is_array($type)) {
                $out.='<select name="'.Security::encode($key).'">';
                foreach($type as $option) $out.='<option value="'.Security::encode($option).'"'.((string)$option===(string)$value?' selected':'').'>'.Security::encode($option).'</option>';
                $out.='</select>';
            } elseif($type==='textarea') $out.='<textarea name="'.Security::encode($key).'" rows="6">'.Security::encode($value).'</textarea>';
            else $out.='<input name="'.Security::encode($key).'" type="'.Security::encode($type).'" value="'.Security::encode($type==='password'?'':$value).'"'.($type==='password'?' autocomplete="new-password"':'').'>';
            $out.='</label>';
        }
        return new Html($out.'<button type="submit">'.Security::encode($button).'</button></form>');
    }
    public static function table(array $headers,array $rows): Html {
        $out='<table><thead><tr>'; foreach($headers as $header) $out.='<th>'.Security::encode($header).'</th>'; $out.='</tr></thead><tbody>';
        foreach($rows as $row) { $out.='<tr>'; foreach($row as $cell) $out.='<td>'.($cell instanceof Html?$cell->value:Security::encode($cell)).'</td>'; $out.='</tr>'; }
        return new Html($out.'</tbody></table>');
    }
    public static function page(string $title,array $content,?array $user=null): string {
        $out='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>'.Security::encode($title).' — VegaDNS</title><link rel="stylesheet" href="assets/app.css"></head><body><header><h1>VegaDNS</h1>';
        if($user) {
            $out.='<p>Signed in as '.Security::encode($user['Email']).'</p><nav>';
            foreach(['domains'=>'Domains','records-new'=>'New domain','users-self'=>'My account','dnsquery'=>'DNS query'] as $mode=>$label) {
                $p=['state'=>'logged_in','mode'=>$mode];
                if($mode==='records-new') $p=['state'=>'logged_in','mode'=>'domains','domain_mode'=>'add'];
                if($mode==='users-self') $p=['state'=>'logged_in','mode'=>'users','user_mode'=>'edit_account','cid'=>$user['cid']];
                $out.=self::link($label,$p)->value.' ';
            }
            if($user['Account_Type']!=='user') foreach(['users'=>'Accounts','default_records'=>'Default records'] as $mode=>$label) $out.=self::link($label,['state'=>'logged_in','mode'=>$mode])->value.' ';
            if(Store::senior($user)) $out.=self::link('Import',['state'=>'logged_in','mode'=>'domains','domain_mode'=>'import_domains'])->value;
            $out.='</nav>'.self::form(['state'=>'end'],[],'Log out')->value;
        }
        $out.='</header><main><h2>'.Security::encode($title).'</h2>';
        foreach($content as $part) $out.=$part instanceof Html?$part->value:'<p>'.Security::encode($part).'</p>';
        return $out.'</main></body></html>';
    }
}
