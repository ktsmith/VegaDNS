<?php
declare(strict_types=1);
if (!defined('VEGADNS_INTERNAL')) { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80300) throw new RuntimeException('PHP 8.3 or later is required (staging floor)');
foreach (['DB','Security','Sessions','Auth','DNS','Store','Network','View','Application','Schema'] as $class) require_once __DIR__.'/'.$class.'.php';
