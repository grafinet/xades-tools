<?php

require __DIR__ . '/../vendor/autoload.php';

use \Symfony\Component\Uid\Uuid;

if (!isset($argv[3])) {
    echo "\n";
    echo "USAGE: php sign.php /path/to/file.pdf /path/to/certificate.p12 certpassword [embed]";
    echo "\n";
    die(1);
}

$file = $argv[1];

if (!file_exists($file)) {
    echo "Error: Missing file {$file}\n";
    exit;
}

$p12 = $argv[2];
$password = $argv[3];;
$embed = isset($argv[4]);

if (!$cert_store = file_get_contents($p12)) {
    echo "Error: Unable to read the cert file\n";
    exit;
}

if (openssl_pkcs12_read($cert_store, $cert_info, $password)) {
    $certPem = $cert_info['cert'];
    $pkey = openssl_pkey_get_private([$cert_info['pkey'], $password]);
} else {
    echo "Error: Unable to read the cert store.\n";
    echo 'OpenSSL: ' . (openssl_error_string()?:'') . "\n";
    exit;
}
/**
 * References between nodes
 */
$ids = [];

// XML files should be in canonical form, if not embedded
$c14n = pathinfo($file, PATHINFO_EXTENSION) === 'xml';

if ($c14n && !$embed) {
    $xml = new DomDocument();
    $xml->load($file);
    $content = $xml->C14n();
} else {
    $content = file_get_contents($file);
}

function sha256($content) {
    return hash('sha256', $content, true);
}

function guid() {
    return 'ID-' . Uuid::v4();
}

$hash = sha256($content);
$digest1 = base64_encode($hash);

// echo "DIGEST FILE:" . $digest1 . "\n";

$certContent = str_replace('-----BEGIN CERTIFICATE-----', '', $certPem);
$certContent = trim(str_replace('-----END CERTIFICATE-----', '', $certContent));
$certFingerprint = base64_encode(sha256(base64_decode($certContent)));

// echo "DIGEST CERT:" . $certFingerprint . "\n";

$info = openssl_x509_parse($certPem);

$certSerial = BCMathExtended\BC::hexdec($info['serialNumberHex']);
$issuerComponents = [];
foreach($info['issuer'] as $componentKey => $componentValue) {
    $issuerComponents[] = $componentKey . '=' . $componentValue;
}
$issuer = implode(',', array_reverse($issuerComponents));

// echo "CERT SERIAL:" . $certSerial . "\n";
// echo "CERT ISSUER:" . $issuer . "\n";

$dom = new \DOMDocument('1.0', 'UTF-8');

// $signatures = $dom->createElement('Signatures');
// $signatures->setAttribute('Id', $ids['all_signatures'] = guid());
// $dom->appendChild($signatures);

$ds = "http://www.w3.org/2000/09/xmldsig#";
$xades = "http://uri.etsi.org/01903/v1.3.2#";

$signature = $dom->createElementNS($ds, 'ds:Signature');
$signature->setAttribute('Id', $ids['signature'] = guid());
// $signatures->appendChild($signature);
$dom->appendChild($signature);

$siginfo = $dom->createElementNS($ds, 'ds:SignedInfo');
$siginfo->setAttribute('Id', guid());
$signature->appendChild($siginfo);

$canon = $dom->createElementNS($ds, 'ds:CanonicalizationMethod', null);
$canon->setAttribute('Algorithm', "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
$siginfo->appendChild($canon);

$sigmet = $dom->createElementNS($ds, 'ds:SignatureMethod', null);
$sigmet->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
$siginfo->appendChild($sigmet);

$ref1 = $dom->createElementNS($ds, 'ds:Reference');
$ref1->setAttribute('Id', $ids['reference1'] = guid());

$siginfo->appendChild($ref1);

if ($c14n || $embed) {
    $transforms = $dom->createElementNS($ds, 'ds:Transforms');
    $ref1->appendChild($transforms);
    $transform = $dom->createElementNS($ds, 'ds:Transform', null);
    $transform->setAttribute('Algorithm', "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
    $transforms->appendChild($transform);
}

if ($embed) {
    $objectEmbed = $dom->createElementNS($ds, 'ds:Object', trim(chunk_split(base64_encode(file_get_contents($file)), 64, "\n")));
    $signature->appendChild($objectEmbed);
    $objectEmbed->setAttribute('Encoding', 'http://www.w3.org/2000/09/xmldsig#base64');
    $objectEmbed->setAttribute('Id', $ids['embedded_object'] = guid());
    $objectEmbed->setAttribute('MimeType', $c14n ? 'text/plain' : 'application/octet-stream');

    $digest1 = base64_encode(sha256($objectEmbed->C14N()));

    $ref1->setAttribute('URI', "#" . $ids['embedded_object']);
} else {
    $ref1->setAttribute('URI', basename($file));
}

$digestMethod = $dom->createElementNS($ds, 'DigestMethod', null);
$digestMethod->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
$ref1->appendChild($digestMethod);
$ref1->appendChild($dom->createElementNS($ds, 'DigestValue', $digest1));

$ref2 = $dom->createElementNS($ds, 'ds:Reference');
$ref2->setAttribute('Id', guid());

$ref2->setAttribute('Type', "http://uri.etsi.org/01903#SignedProperties");
$siginfo->appendChild($ref2);

$digestMethod2 = $dom->createElementNS($ds, 'DigestMethod', null);
$digestMethod2->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
$ref2->appendChild($digestMethod2);

$sigval = $dom->createElementNS($ds, 'ds:SignatureValue', null);
$sigval->setAttribute('Id', guid());
$signature->appendChild($sigval);

$ki = $dom->createElementNS($ds, 'ds:KeyInfo');
$signature->appendChild($ki);

$x509data = $dom->createElementNS($ds, 'ds:X509Data');
$ki->appendChild($x509data);
$x509data->appendChild($dom->createElementNS($ds, 'ds:X509Certificate', $certContent));

$object = $dom->createElementNS($ds, 'ds:Object');
$signature->appendChild($object);

$qp = $dom->createElementNS($xades, 'xades:QualifyingProperties');
$qp->setAttribute('Id', guid());
$qp->setAttribute('Target', "#" . $ids['signature']);
$object->appendChild($qp);

$sp = $dom->createElementNS($xades,'xades:SignedProperties');
$sp->setAttribute('Id', $ids['signed_properties'] = guid());
$qp->appendChild($sp);

$ref2->setAttribute('URI', "#" . $ids['signed_properties']);

$ssp = $dom->createelementNS($xades, 'xades:SignedSignatureProperties');
$sp->appendChild($ssp);

$ssp->appendChild($dom->createelementNS($xades, 'xades:SigningTime', date('Y-m-d\TH:i:sp'))); // '2022-04-01T08:54:19Z'

$sc = $dom->createelementNS($xades, 'xades:SigningCertificate');
$ssp->appendChild($sc);

$xcert = $dom->createelementNS($xades, 'xades:Cert');
$sc->appendChild($xcert);

$xcd = $dom->createelementNS($xades, 'xades:CertDigest');
$xcert->appendChild($xcd);

$dm = $dom->createelementNS($ds, 'ds:DigestMethod', null);
$dm->setAttribute('Algorithm', "http://www.w3.org/2001/04/xmlenc#sha256");
$xcd->appendChild($dm);
$xcd->appendChild($dom->createelementNS($ds, 'ds:DigestValue', $certFingerprint));

$xs = $dom->createelementNS($xades, 'xades:IssuerSerial');
$xcert->appendChild($xs);

$xs->appendChild($dom->createelementNS($ds, 'ds:X509IssuerName', $issuer));
$xs->appendChild($dom->createelementNS($ds, 'ds:X509SerialNumber', $certSerial));

$sdop = $dom->createelementNS($xades, 'xades:SignedDataObjectProperties');
$sp->appendChild($sdop);

$dof = $dom->createelementNS($xades, 'xades:DataObjectFormat');
$dof->setAttribute('ObjectReference', "#" . $ids['reference1']);
$sdop->appendChild($dof);

if ($c14n) {
    $dof->appendChild($dom->createelementNS($xades, 'xades:Description', 'Dokument w formacie xml [XML]'));
    $dof->appendChild($dom->createelementNS($xades, 'xades:MimeType', 'text/plain'));
} else {
    $dof->appendChild($dom->createelementNS($xades, 'xades:Description', 'Plik graficzny [JPG]'));
    $dof->appendChild($dom->createelementNS($xades, 'xades:MimeType', 'application/octet-stream'));
}
if ($embed) {
    $dof->appendChild($dom->createelementNS($xades, 'xades:Encoding', 'http://www.w3.org/2000/09/xmldsig#base64'));
} else {
    $cti = $dom->createelementNS($xades, 'xades:CommitmentTypeIndication');
    $sdop->appendChild($cti);

    $ctypeId = $dom->createelementNS($xades, 'xades:CommitmentTypeId');
    $cti->appendChild($ctypeId);

    $ctypeId->appendChild($dom->createelementNS($xades, 'xades:Identifier', 'http://uri.etsi.org/01903/v1.2.2#ProofOfApproval'));
    $cti->appendChild($dom->createelementNS($xades, 'xades:AllSignedDataObjects', null));
}

$sptodigest = $sp->C14N();

// echo "\n" . $sptodigest . "\n";

$xmlDigest = base64_encode(sha256($sptodigest));

$ref2->appendChild($dom->createElementNS($ds, 'DigestValue', $xmlDigest));

// echo "XML DIGEST:" . $xmlDigest . "\n";

$actualDigest = null;
openssl_sign(
    $siginfo->C14N(),
    $actualDigest,
    $pkey,
    'sha256WithRSAEncryption'
);

$sigval->textContent = chunk_split(base64_encode($actualDigest), 64, "\n");

//$canonicalizedXml = $dom->C14N();

//echo "\n";
//echo $canonicalizedXml;
//exit;
// echo "\n";

file_put_contents($file . '.XAdES', $dom->saveXML());
