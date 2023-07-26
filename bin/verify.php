<?php

use XadesTools\Verification;

require __DIR__ . '/../vendor/autoload.php';

if (!isset($argv[1])) {
    echo "\n";
    echo "USAGE: php bin/verify.php /path/to/file.jpg.XAdES [verbose] [load-content]";
    echo "\nverbose - print info about time and signing subject";
    echo "\nload-content - loads content from file, only for embedded objects";
    echo "\n";
    exit(1);
}

$file = $argv[1];

if (!file_exists($file)) {
    echo "Error: Missing file {$file}\n";
    exit(2);
}

function toBool(string $value): bool {
    $value = strtolower($value);
    if ($value === 'false' || $value === 'no' || $value === 'nie' || $value === 'n') {
        return false;
    }
    return boolval($value);
}

$verbose = isset($argv[2]) && toBool($argv[2]);
$loadContent = isset($argv[3]) && toBool($argv[3]);

$xades = new Verification();
try {
    if ($loadContent) {
        $res = $xades->verifyXml(file_get_contents($file));
    } else {
        $res = $xades->verifyFile($file);
    }
    if ($res) {
        echo "OK\n";
        if ($verbose) {
            var_dump($res->signingSubject, $res->dateSigned);
            echo "\n";
        }
        exit(0);
    } else {
        echo "FAIL";
        exit(3);
    }
} catch (Throwable $t) {
    echo 'ERROR: ' . $t->getMessage();
    exit(255);
}
