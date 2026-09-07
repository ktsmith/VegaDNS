<?php
http_response_code(410);
header('Content-Type: text/plain; charset=UTF-8');
header('Cache-Control: no-store');
echo "This endpoint has been retired.\n";
