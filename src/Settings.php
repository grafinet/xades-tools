<?php
declare(strict_types=1);

namespace XadesTools;

class Settings
{
    public function __construct(
        private readonly string $certPath,
        private readonly string $password
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
}
