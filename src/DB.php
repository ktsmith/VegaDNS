<?php
declare(strict_types=1);
namespace VegaDNS;
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }

final class DB
{
    public function __construct(public readonly \PDO $pdo) {
        $pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        if ($pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql') {
            $pdo->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false);
        }
    }
    public function run(string $sql, array $params = []): \PDOStatement {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }
    public function one(string $sql, array $params = []): ?array {
        return $this->run($sql, $params)->fetch() ?: null;
    }
    public function all(string $sql, array $params = []): array { return $this->run($sql, $params)->fetchAll(); }
    public function transaction(callable $operation): mixed {
        $this->pdo->beginTransaction();
        try { $result = $operation(); $this->pdo->commit(); return $result; }
        catch (\Throwable $e) { if ($this->pdo->inTransaction()) $this->pdo->rollBack(); throw $e; }
    }
}
