<?php

namespace XadesTools;

use Symfony\Component\Uid\Uuid;

class Tools
{
    public const DATE_FORMAT = 'Y-m-d\TH:i:sp';
    public const NAMESPACE_DS = "http://www.w3.org/2000/09/xmldsig#";
    public const NAMESPACE_XADES = "http://uri.etsi.org/01903/v1.3.2#";
    public const KNOWN_ALGORITHMS = [
        "http://www.w3.org/2000/09/xmldsig#sha1" => 'sha1',
        "http://www.w3.org/2001/04/xmlenc#sha256" => 'sha256',
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => 'sha1WithRSAEncryption',
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => 'sha256WithRSAEncryption',
    ];
    public const TYPE_SIGNED_PROPERTIES = 'http://uri.etsi.org/01903#SignedProperties';
    public const ENCODING_BASE64 = 'http://www.w3.org/2000/09/xmldsig#base64';

    public static function guid(): string
    {
        return 'ID-' . Uuid::v4();
    }

    public static function sha256($content): string
    {
        return hash('sha256', $content, true);
    }
}