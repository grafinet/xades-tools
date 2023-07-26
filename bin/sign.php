<?php

use XadesTools\Settings;
use XadesTools\Signature;

require __DIR__ . '/../vendor/autoload.php';

if (!isset($argv[3])) {
    echo "\n";
    echo "USAGE: php bin/sign.php /path/to/file.pdf /path/to/certificate.p12 cert-password [embed] [load-content]";
    echo "\nembed - embeds file in resulting xades file";
    echo "\nload-content - loads content from file and signs it as embedded object";
    echo "\n";
    exit(1);
}

$file = $argv[1];

if (!file_exists($file)) {
    echo "Error: Missing source file {$file}\n";
    exit(2);
}
if (!file_exists($argv[2])) {
    echo "Error: Missing certificate file {$argv[2]}\n";
    exit(2);
}

$embed = isset($argv[4]);
$loadContent = isset($argv[5]);
try {
    $xades = new Signature(
        new Settings($argv[2], $argv[3])
    );
    if ($embed && $loadContent) {
        $content = file_get_contents($file);
        $result = file_put_contents($file . '.XAdES', $xades->signXml($content), pathinfo($file, PATHINFO_EXTENSION));
    } else {
        $result = file_put_contents($file . '.XAdES', $xades->signFile($file, $embed));
    }
    exit($result ? 0 : 3);
} catch (Throwable $t) {
    echo $t->getMessage() . "\n";
    foreach ($t->getTrace() as $trace) {
        print_r($trace);
    }
    exit(255);
}

