<?php

use XadesTools\Verification;

require __DIR__ . '/../vendor/autoload.php';

if (!isset($argv[2])) {
    echo "\n";
    echo "USAGE: php bin/extract.php /path/to/file.jpg.XAdES /path/to/save/embedded_file.xml";
    echo "\n";
    exit(1);
}

$file = $argv[1];
$output = $argv[2];

if (!file_exists($file)) {
    echo "Error: Missing file {$file}\n";
    exit(2);
}

$xades = new Verification();
try {
    $res = $xades->verifyFile($file);
    if ($res) {
        if (!file_put_contents($output, $res->content)) {
            echo "Failed to save file {$output}\n";
            exit(2);
        }
        echo "OK\n";
        exit(0);
    } else {
        echo "FAIL";
        exit(3);
    }
} catch (Throwable $t) {
    echo 'ERROR: ' . $t->getMessage();
    exit(255);
}
