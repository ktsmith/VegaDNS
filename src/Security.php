<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class HttpError extends \RuntimeException {
    public function __construct(public readonly int $status, string $message) { parent::__construct($message); }
}
final class Security
{
    public static function text(array $input, string $key, string $default = ''): string {
        $value = $input[$key] ?? $default;
        if (!is_string($value) || strlen($value) > 65536 || !preg_match('//u', $value)) {
            throw new HttpError(400, 'Invalid input.');
        }
        return $value;
    }
    public static function integer(mixed $value, int $min = 0, int $max = 2147483647): int {
        if ((!is_string($value) && !is_int($value)) || !preg_match('/\A[0-9]{1,10}\z/D', (string)$value)) {
            throw new HttpError(400, 'Expected a non-negative integer.');
        }
        $n = (int)$value;
        if ($n < $min || $n > $max) throw new HttpError(400, 'Number out of range.');
        return $n;
    }
    public static function choice(string $value, array $allowed): string {
        if (!in_array($value, $allowed, true)) throw new HttpError(400, 'Invalid selection.');
        return $value;
    }
    public static function email(string $email): string {
        $email = strtolower(trim($email));
        if (strlen($email) > 60 || !filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email)) {
            throw new HttpError(400, 'Invalid email address.');
        }
        return $email;
    }
    public static function password(string $password): string {
        if (strlen($password) < 12 || strlen($password) > 72 || str_contains($password, "\0")) {
            throw new HttpError(400, 'Passwords must contain 12–72 bytes.');
        }
        return password_hash($password, PASSWORD_DEFAULT);
    }
    public static function encode(mixed $value): string {
        return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
    public static function url(array $params = []): string { return 'index.php?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986); }
    public static function csrf(): string {
        return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }
    public static function requirePost(string $method, array $post): void {
        if ($method !== 'POST') throw new HttpError(405, 'This action requires POST.');
        $token = self::text($post, 'csrf');
        if (!isset($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $token)) {
            throw new HttpError(403, 'Invalid or expired form. Reload the page and try again.');
        }
    }
    public static function requireOrigin(?string $origin, string $baseUrl): void {
        if($origin===null || $origin==='null') return; // Non-browser clients still need the CSRF token. null=bfcache/privacy browsers
        $parts=parse_url($baseUrl);
        $expected=$parts['scheme'].'://'.$parts['host'].(isset($parts['port'])?':'.$parts['port']:'');
        if(!hash_equals($expected,$origin)) throw new HttpError(403,'Cross-origin form rejected.');
    }
    public static function audit(string $event, ?int $cid = null): void {
        // Do not log URLs, SQL, user input, passwords, reset tokens or session IDs.
        error_log(json_encode(['event' => $event, 'cid' => $cid, 'time' => time()], JSON_THROW_ON_ERROR));
    }
    public static function startSession(array $config, DB $db): void {
        ini_set('session.use_cookies', '1'); ini_set('session.use_only_cookies', '1');
        ini_set('session.use_strict_mode', '1'); ini_set('session.use_trans_sid', '0');
        ini_set('session.gc_maxlifetime', (string)$config['timeout']);
        session_name('VDNSSessid');
        session_set_cookie_params(['lifetime'=>0, 'path'=>$config['cookie_path'], 'secure'=>true, 'httponly'=>true, 'samesite'=>'Lax']);
        if ($config['sessions'] === 'mysql') {
            session_set_save_handler(new Sessions($db), true);
        } else {
            if (!is_dir($config['session_dir']) || !is_writable($config['session_dir'])) {
                throw new \RuntimeException('Session storage unavailable');
            }
            session_save_path($config['session_dir']);
        }
        if (!session_start()) throw new \RuntimeException('Session startup failed');
        self::csrf();
    }
    public static function clearIdentity(): void { unset($_SESSION['cid'], $_SESSION['auth_version'], $_SESSION['login_time']); }
}
