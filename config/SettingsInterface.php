<?php

namespace config;

interface SettingsInterface
{
    public function getCertPath(): string;

    public function getPassword(): string;

    public function isEmbed(): bool;
}