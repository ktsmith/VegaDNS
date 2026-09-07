<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Auth
{
    public function __construct(private DB $db, private array $config) {}
    public function current(): ?array {
        if (empty($_SESSION['cid']) || ($_SESSION['login_time'] ?? 0) < time()-$this->config['timeout']) return null;
        $user = $this->db->one('SELECT * FROM accounts WHERE cid=? AND Status=?', [$_SESSION['cid'], 'active']);
        if (!$user || (int)$user['auth_version'] !== ($_SESSION['auth_version'] ?? null)) {
            Security::clearIdentity(); return null;
        }
        return $user;
    }
    public function limit(string $action, string $identity, int $maximum, int $seconds): bool {
        // One atomic counter increment, shared across workers and both session backends.
        $key = hash('sha256', $action . "\0" . $identity); $now = time();
        try { $this->db->run('INSERT INTO auth_limits (bucket, started, hits) VALUES (?, ?, 0)', [$key, $now]); }
        catch (\PDOException $e) { if (!str_starts_with((string)$e->getCode(), '23')) throw $e; }
        $this->db->run('UPDATE auth_limits SET hits=CASE WHEN started < ? THEN 1 ELSE hits+1 END, started=CASE WHEN started < ? THEN ? ELSE started END WHERE bucket=?', [$now-$seconds, $now-$seconds, $now, $key]);
        return (int)$this->db->one('SELECT hits FROM auth_limits WHERE bucket=?', [$key])['hits'] <= $maximum;
    }
    public function login(string $email, string $password, string $ip): bool {
        $email = strtolower(trim($email));
        $allowedIp = $this->limit('login-ip', $ip, 40, 900);
        $allowedAccount = $this->limit('login-account', $email, 10, 900);
        if (!$allowedIp || !$allowedAccount) { Security::audit('login_throttled'); return false; }
        $user = $this->db->one('SELECT * FROM accounts WHERE Email=? AND Status=?', [$email, 'active']);
        $hash = $user['Password'] ?? '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2uheWG/igi.';
        $legacy = $user && preg_match('/\A[a-f0-9]{32}\z/', $hash);
        $valid = $legacy ? hash_equals($hash, md5($password)) : password_verify($password, $hash);
        if (!$user || !$valid || strlen($password) > 72 || str_contains($password, "\0")) { Security::audit('login_failed'); return false; }
        if ($legacy || password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            $this->db->run('UPDATE accounts SET Password=? WHERE cid=? AND Password=?', [password_hash($password, PASSWORD_DEFAULT), $user['cid'], $hash]);
        }
        // A concurrent revocation cannot be undone: current() rechecks the version.
        if (!session_regenerate_id(true)) throw new \RuntimeException('Session rotation failed');
        $_SESSION = ['cid'=>(int)$user['cid'], 'auth_version'=>(int)$user['auth_version'], 'login_time'=>time(), 'csrf'=>bin2hex(random_bytes(32))];
        Security::audit('login_success', (int)$user['cid']); return true;
    }
    public function requestReset(string $email, string $ip, callable $send): void {
        $email = strtolower(trim($email));
        $allowIp = $this->limit('reset-ip', $ip, 20, 3600);
        $allowAccount = $this->limit('reset-account', $email, 3, 3600);
        if (!$allowIp || !$allowAccount) { Security::audit('reset_throttled'); return; }
        $user = $this->db->one('SELECT cid, Email FROM accounts WHERE Email=? AND Status=?', [$email, 'active']);
        if (!$user) return;
        $token = bin2hex(random_bytes(32));
        $this->db->run('INSERT INTO password_resets (token_hash, cid, expires) VALUES (?, ?, ?)', [hash('sha256', $token), $user['cid'], time()+1800]);
        $send($user['Email'], $this->config['base_url'].'?'.http_build_query(['state'=>'reset','token'=>$token], '', '&', PHP_QUERY_RFC3986));
        Security::audit('reset_requested', (int)$user['cid']);
    }
    public function reset(string $token, string $password): bool {
        $hash = Security::password($password);
        if (!preg_match('/\A[a-f0-9]{64}\z/', $token)) return false;
        return $this->db->transaction(function () use ($token, $hash) {
            $digest = hash('sha256', $token);
            $reset = $this->db->one('SELECT cid FROM password_resets WHERE token_hash=? AND expires>?', [$digest, time()]);
            if (!$reset) return false;
            if ($this->db->run('DELETE FROM password_resets WHERE token_hash=? AND expires>?', [$digest, time()])->rowCount() !== 1) return false;
            $changed = $this->db->run('UPDATE accounts SET Password=?, auth_version=auth_version+1 WHERE cid=? AND Status=?', [$hash, $reset['cid'], 'active'])->rowCount();
            $this->db->run('DELETE FROM password_resets WHERE cid=?', [$reset['cid']]);
            Security::clearIdentity();
            Security::audit('reset_completed', (int)$reset['cid']); return $changed === 1;
        });
    }
}
