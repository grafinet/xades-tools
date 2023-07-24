<?php
declare(strict_types=1);

namespace XadesTools\Factory;

use XadesTools\Certificate;
use XadesTools\Exception\CertificateException;

class CertificateFactory
{
    public static function load(string $certPath, string $password) {

        if(!$certStorage = file_get_contents($certPath)) {
            throw new CertificateException('Unable to read the cert file');
        }

        if (openssl_pkcs12_read($certStorage, $certificates, $password)) {
            $certificate = new Certificate();
            $certificate->setCertificate($certificates['cert']);
            $certificate->generatePkey($certificates['pkey'], $password);

        } else {
            throw new CertificateException(\sprintf('Unable to read the cert file \\n. OpenSSL: %s', (openssl_error_string()?:'') ));
        }

        return $certificate->load($certPath, $password);
    }
}