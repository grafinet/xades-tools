<?php
declare(strict_types=1);

namespace XadesTools;

use config\SettingsInterface;
use XadesTools\Factory\CertificateFactory;

require __DIR__ . '/../vendor/autoload.php';

class XadesTools
{
    private SettingsInterface $settings;

    public function __construct(\config\SettingsInterface $settings)
    {
        $this->settings = $settings;
    }

    public function sign(string $filePath): void
    {
        $certificate = CertificateFactory::load($this->settings->getCertPath(), $this->settings->getPassword());

    }

    public function verify(string $filePath): void
    {

    }
}