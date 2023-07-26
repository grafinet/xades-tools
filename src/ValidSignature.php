<?php

namespace XadesTools;

use DateTimeInterface;

class ValidSignature
{

    public function __construct(
        public readonly array $signingSubject,
        public readonly DateTimeInterface $dateSigned,
        public readonly ?string $content = null
    )
    {
    }
}