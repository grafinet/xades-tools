<?php
declare(strict_types=1);

namespace XadesTools;
use XadesTools\Exception\CertificateException;

class Certificate
{
    private string $certificate;
    private ?\OpenSSLAsymmetricKey $pkey;
    private string $content;
    private string $fingerPrint;
    public function load(string $certPath, string $password){

        return $this;
    }

    /**
     * @return string
     */
    public function getCertificate(): string
    {
        return $this->certificate;
    }

    /**
     * @param string $certificate
     */
    public function setCertificate(string $certificate): void
    {
        $this->certificate = $certificate;
    }

    /**
     * @return \OpenSSLAsymmetricKey|null
     */
    public function getPkey(): ?\OpenSSLAsymmetricKey
    {
        return $this->pkey;
    }

    /**
     * @param \OpenSSLAsymmetricKey|null $pkey
     */
    public function setPkey(?\OpenSSLAsymmetricKey $pkey): void
    {
        $this->pkey = $pkey;
    }

    /**
     * @return string
     */
    public function getContent(): string
    {
        return $this->content;
    }

    /**
     * @param string $content
     */
    public function setContent(string $content): void
    {

        $this->content = $content;
    }

    /**
     * @return string
     */
    public function getFingerPrint(): string
    {
        return $this->fingerPrint;
    }

    /**
     * @param string $fingerPrint
     */
    public function setFingerPrint(string $fingerPrint): void
    {
        $this->fingerPrint = $fingerPrint;
    }

    public function generatePkey($pkey, string $password): void
    {
        $this->setPkey(openssl_pkey_get_private([$pkey, $password]));
    }
}