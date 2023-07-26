<?php
declare(strict_types=1);

namespace XadesTools\Factory;

use XadesTools\Certificate;
use XadesTools\Exception\CertificateException;

use function file_get_contents;
use function openssl_error_string;
use function openssl_pkcs12_read;
use function openssl_x509_parse;
use function sprintf;

class CertificateFactory
{
    /**
     * @param string $certPath
     * @param string $password
     * @return Certificate
     * @throws CertificateException
     */
    public static function load(string $certPath, string $password): Certificate
    {
        if (!($certStorage = file_get_contents($certPath))) {
            throw new CertificateException('Unable to read the cert file');
        }

        if (openssl_pkcs12_read($certStorage, $certificateInfo, $password)) {
            $certificate = new Certificate(
                $certificateInfo,
                openssl_pkey_get_private([$certificateInfo['pkey'], $password])
            );
            $certificate->setCertificateInfo(openssl_x509_parse($certificateInfo['cert']));

        } else {
            throw new CertificateException(sprintf('Unable to read the cert file \\n. OpenSSL: %s', (openssl_error_string() ?: '')));
        }

        return $certificate;
    }
}