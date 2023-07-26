<?php

namespace XadesTools;

use DateTimeImmutable;
use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use RuntimeException;
use XadesTools\Exception\XadesException;

use function dirname;
use function hash;
use function openssl_error_string;
use function openssl_verify;
use function openssl_x509_parse;
use function sprintf;
use function str_starts_with;
use function substr;

class Verification
{
    private ?string $fileName;

    /**
     * @param string $filePath
     * @return ValidSignature|false
     * @throws RuntimeException
     */
    public function verifyFile(string $filePath): ValidSignature|false
    {
        $dom = new DomDocument();
        if (!$dom->load($filePath)) {
            throw new RuntimeException("Invalid XML content in ".$filePath);
        }
        $this->fileName = $filePath;
        return $this->verifyDomDocument($dom);
    }

    /**
     * @param string $content
     * @return ValidSignature|false
     * @throws RuntimeException
     */
    public function verifyXml(string $content): ValidSignature|false
    {
        $dom = new DomDocument();
        if (!$dom->loadXML($content)) {
            throw new RuntimeException("Invalid XML content");
        }
        $this->fileName = null;
        return $this->verifyDomDocument($dom);
    }

    /**
     * @param DomDocument $dom
     * @return ValidSignature|false
     * @throws XadesException
     */
    public function verifyDomDocument(DomDocument $dom): ValidSignature|false
    {
        $xpath = new DOMXPath($dom);
        $elementsById = [];
        foreach ($xpath->query("//*[@Id]") as $element) {
            $id = $element->attributes->getNamedItem('Id')->nodeValue;
            $elementsById[$id] = $element;
        }
        $content = '';
        $references = $dom->getElementsByTagNameNS(Tools::NAMESPACE_DS,'Reference');
        if (!$references->count()) {
            throw new XadesException(sprintf("Missing 'Reference' nodes in '%s' namespace", Tools::NAMESPACE_DS));
        }
        foreach ($references as $reference) {
            /** @var DOMElement $reference */
            $target = $reference->attributes->getNamedItem('URI')->nodeValue;
            $isActualContent = ($reference->attributes->getNamedItem('Type')->nodeValue ?? null) != Tools::TYPE_SIGNED_PROPERTIES;
            $transforms = (bool)$reference->getElementsByTagNameNS(Tools::NAMESPACE_DS, 'Transform')->length;
            $hashFunc = $reference->getElementsByTagNameNS(Tools::NAMESPACE_DS, 'DigestMethod')->item(0)->attributes->getNamedItem('Algorithm')->nodeValue;
            $digestValue = $reference->getElementsByTagNameNS(Tools::NAMESPACE_DS, 'DigestValue')->item(0)->nodeValue;
            if (str_starts_with($target, '#')){
                $targetId = substr($target, 1);
                /** @var DOMNode $digestSubjectNode */
                $digestSubjectNode = $elementsById[$targetId];
                $digestSubject = $digestSubjectNode->C14N();
                if ($isActualContent) {
                    if ($digestSubjectNode->attributes->getNamedItem('Encoding')->nodeValue ?? null == Tools::ENCODING_BASE64) {
                        $content = base64_decode($digestSubjectNode->nodeValue);
                    } else {
                        $content = $digestSubjectNode->nodeValue;
                    }
                }
            } elseif (!$this->fileName) {
                throw new XadesException(sprintf("Missing file referenced by URI: %s", $target));
            } else {
                $digestSubject = file_get_contents(dirname($this->fileName) . '/' . $target);
                if ($transforms) {
                    $dom2 = new DOMDocument();
                    $dom2->loadXML($digestSubject);
                    $digestSubject = $dom2->C14N();
                    if ($isActualContent) {
                        $content = $digestSubject;
                    }
                } elseif ($isActualContent) {
                    $content = $digestSubject;
                }
            }
            if (!isset(Tools::KNOWN_ALGORITHMS[$hashFunc])) {
                throw new XadesException("Unsupported digest hash function {$hashFunc}!");
            }
            $calculatedDigest = hash(Tools::KNOWN_ALGORITHMS[$hashFunc], $digestSubject, true);
            if (base64_decode($digestValue) !== $calculatedDigest) {
                throw new XadesException("Invalid digest in {$target}!");
            }
        }
        $x509 = $dom->getElementsByTagNameNS(Tools::NAMESPACE_DS,'X509Certificate');
        if (!$x509->count()) {
            throw new XadesException(sprintf("Missing 'X509Certificate' node in %s namespace", Tools::NAMESPACE_DS));
        }
        $certContent = trim($x509->item(0)->textContent);
        $certPem = <<<EOCERT
-----BEGIN CERTIFICATE-----
{$certContent}
-----END CERTIFICATE-----
EOCERT;

        $public = openssl_pkey_get_public($certPem);

        $subject = $dom->getElementsByTagNameNS(Tools::NAMESPACE_DS,'SignedInfo')->item(0)->C14N();
        $signature = base64_decode(
            $dom->getElementsByTagNameNS(Tools::NAMESPACE_DS,'SignatureValue')->item(0)->textContent
        );
        $signMethod = $dom->getElementsByTagNameNS(Tools::NAMESPACE_DS,'SignatureMethod')
            ->item(0)->attributes->getNamedItem('Algorithm')->nodeValue;

        if (!isset(Tools::KNOWN_ALGORITHMS[$signMethod])) {
            throw new XadesException("Unsupported signature hash method {$signMethod}!!");
        }

        $res = openssl_verify($subject, $signature, $public, Tools::KNOWN_ALGORITHMS[$signMethod]);
        if (-1 == $res) {
            throw new XadesException('Verification error: ' . (openssl_error_string()?:''));
        } elseif ($res) {
            $signTime = trim($dom->getElementsByTagNameNS(Tools::NAMESPACE_XADES,'SigningTime')->item(0)->textContent);
            $certInfo = openssl_x509_parse($certPem);
            return new ValidSignature(
                $certInfo['subject'],
                DateTimeImmutable::createFromFormat(Tools::DATE_FORMAT, $signTime),
                $content
            );
        }
        return false;
    }
}
