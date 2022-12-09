<?php

require __DIR__ . '/../vendor/autoload.php';

if (!isset($argv[1])) {
    echo "\n";
    echo "USAGE: php verify.php /path/to/file.pdf.XAdES [verbose]";
    echo "\n";
    die(1);
}
$file = $argv[1];

if (!file_exists($file)) {
    echo "Error: Missing file {$file}\n";
    exit;
}

$dom = new DomDocument();
$dom->load($file);
// DomDocument::getElementById does not work without doctype declarations
$xpath = new DOMXPath($dom);
$elementsById = [];
foreach ($xpath->query("//*[@Id]") as $element) {
    $id = $element->attributes->getNamedItem('Id')->nodeValue;
    $elementsById[$id] = $element;
}

$ds = "http://www.w3.org/2000/09/xmldsig#";
$xades = "http://uri.etsi.org/01903/v1.3.2#";
$algorithms = [
    "http://www.w3.org/2000/09/xmldsig#sha1" => 'sha1',
    "http://www.w3.org/2001/04/xmlenc#sha256" => 'sha256',
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => 'sha1WithRSAEncryption',
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => 'sha256WithRSAEncryption',
];

foreach ($dom->getElementsByTagNameNS($ds,'Reference') as $reference) {
    /** @var  DOMElement $reference */
    $target = $reference->attributes->getNamedItem('URI')->nodeValue;
    $transforms = (bool)$reference->getElementsByTagNameNS($ds, 'Transform')->length;
    $hashFunc = $reference->getElementsByTagNameNS($ds, 'DigestMethod')->item(0)->attributes->getNamedItem('Algorithm')->nodeValue;
    $digestValue = $reference->getElementsByTagNameNS($ds, 'DigestValue')->item(0)->nodeValue;
    if (str_starts_with($target, '#')){
        $targetId = substr($target, 1);
        $digestSubject = $elementsById[$targetId];
        $digestSubject = $digestSubject->C14N();
    } else {
        $digestSubject = file_get_contents(\dirname($file) . '/' . $target);
        if ($transforms) {
            $dom2 = new DOMDocument();
            $dom2->loadXML($digestSubject);
            $digestSubject = $dom2->C14N();
        }
    }
    if (!isset($algorithms[$hashFunc])) {
        echo "\nUnsupported digest hash function {$hashFunc}!\n";
        die;
    }
    $calculatedDigest = hash($algorithms[$hashFunc], $digestSubject, true);
    if (base64_decode($digestValue) !== $calculatedDigest) {
        echo "\nInvalid digest in {$target}!\n";
        die;
    }
}

$certContent = \trim($dom->getElementsByTagNameNS($ds,'X509Certificate')->item(0)->textContent);
$certPem = <<<EOCERT
-----BEGIN CERTIFICATE-----
{$certContent}
-----END CERTIFICATE-----
EOCERT;

$public = openssl_pkey_get_public($certPem);

$subject = $dom->getElementsByTagNameNS($ds,'SignedInfo')->item(0)->C14N();
$signature = base64_decode($dom->getElementsByTagNameNS($ds,'SignatureValue')->item(0)->textContent);
$signMethod = $dom->getElementsByTagNameNS($ds,'SignatureMethod')->item(0)->attributes->getNamedItem('Algorithm')->nodeValue;

if (!isset($algorithms[$signMethod])) {
    echo "\nUnsupported signature hash method {$signMethod}!\n";
    die;
}

$res = openssl_verify($subject, $signature, $public, $algorithms[$signMethod]);

if ($res == -1) {
    echo 'Verification error: ' . (openssl_error_string()?:'') . "\n";
} elseif ($res) {
    echo "OK\n";
    if (isset($argv[2])) {
        $signTime = \trim($dom->getElementsByTagNameNS($xades,'SigningTime')->item(0)->textContent);
        echo "Data podpisu {$signTime}\n";
        echo "Podpisujący: \n";
        $certInfo = openssl_x509_parse($certPem);
        print_r($certInfo['subject']);
    }
} else {
    echo "Invalid signature";
}
