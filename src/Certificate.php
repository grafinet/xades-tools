<?php
declare(strict_types=1);

namespace XadesTools;

use BCMathExtended\BC;
use OpenSSLAsymmetricKey;

use function array_reverse;
use function implode;
use function str_replace;
use function trim;

class Certificate
{
    private string $certificate;
    private array $certificateInfo;
    private ?OpenSSLAsymmetricKey $privateKey;

    public function __construct(array $certificateInfo, OpenSSLAsymmetricKey $privateKey)
    {
        $this->certificate = trim(
            str_replace(
                ['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'],
                '',
                $certificateInfo['cert']
            )
        );
        $this->setPrivateKey($privateKey);
    }

    public function getCertificate(): string
    {
        return $this->certificate;
    }

    public function getCertificateInfo(): array
    {
        return $this->certificateInfo;
    }

    public function setCertificateInfo(array $certificateInfo): void
    {
        $this->certificateInfo = $certificateInfo;
    }

    public function getSerialNumber(): string
    {
        return BC::hexdec($this->certificateInfo['serialNumberHex']);
    }

    public function getIssuer(): string
    {
        $issuerComponents = [];
        foreach ($this->certificateInfo['issuer'] as $componentKey => $componentValue) {
            $issuerComponents[] = $componentKey . '=' . $componentValue;
        }
        return implode(',', array_reverse($issuerComponents));
    }

    /**
     * @return OpenSSLAsymmetricKey|null
     */
    public function getPrivateKey(): ?OpenSSLAsymmetricKey
    {
        return $this->privateKey;
    }

    /**
     * @param OpenSSLAsymmetricKey|null $pkey
     */
    private function setPrivateKey(?OpenSSLAsymmetricKey $pkey): void
    {
        $this->privateKey = $pkey;
    }

    /**
     * @return string
     */
    public function getFingerPrint(): string
    {
        return base64_encode(
            Tools::sha256(base64_decode($this->certificate))
        );
    }
}
