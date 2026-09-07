<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class Sessions implements \SessionHandlerInterface, \SessionUpdateTimestampHandlerInterface
{
    public function __construct(private DB $db) {}
    public function open(string $path, string $name): bool { return true; }
    public function close(): bool { return true; }
    public function read(string $id): string { return $this->db->one('SELECT data FROM web_sessions WHERE id=?', [$id])['data'] ?? ''; }
    public function write(string $id, string $data): bool {
        $this->db->run('REPLACE INTO web_sessions (id, access, data) VALUES (?, ?, ?)', [$id, time(), $data]); return true;
    }
    public function destroy(string $id): bool { $this->db->run('DELETE FROM web_sessions WHERE id=?', [$id]); return true; }
    public function gc(int $max_lifetime): int|false { return $this->db->run('DELETE FROM web_sessions WHERE access < ?', [time()-$max_lifetime])->rowCount(); }
    public function validateId(string $id): bool { return $this->db->one('SELECT id FROM web_sessions WHERE id=?', [$id]) !== null; }
    public function updateTimestamp(string $id, string $data): bool { $this->db->run('UPDATE web_sessions SET access=? WHERE id=?', [time(), $id]); return true; }
}
