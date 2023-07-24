<?php
declare(strict_types=1);

namespace config;

class Settings implements SettingsInterface
{
    private const DEFAULT_CERT_STORE = '../var/cert_storage';

    public function __construct(
        private readonly string $certPath = '',
        private readonly string $password = '',
        private readonly bool $embed = false
    )
    {}
    public function getCertPath(): string
    {
        return $this->certPath;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function isEmbed(): bool
    {
        return $this->embed;
    }
}