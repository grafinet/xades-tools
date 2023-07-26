# API:

### Signing

```php
use XadesTools\Settings;
use XadesTools\Signature;
$settings = new Settings($pathToCertificate, $passphrase);
$xades = new Signature($settings);
$signedXmlAsString = $xades->signFile($file, $embed);
```

### Verification, content extraction

```php
use XadesTools\Verification;
$xades = new Verification();
$result = $xades->verifyFile($pathToXadesFile);
if ($result) {
    $content = $res->content; // binary content or plain text for xml files
    $signTime = $res->dateSigned; // DateTime object
    $signingSubject = $res->signingSubject; // array
} else {
    // Signature does not match signed content
}
```

# COMMAND LINE USAGE:

### Signing file
```shell
php bin/sign.php file cert pass [embed] [load-content]
```
Where:
- `file` - path to file we want to sign. Signature will be created in the same folder, with .XAdES extension
- `cert` - certificate in PKCS#12 format (.p12) - with private key
- `pass` - password for p12 file
- `embed` - if true, signature will embed given file
- `load-content` - loads file content into variable and signs it as embedded object

Results in `file.XAdES` located in the same directory as given `file`

### Verification

```shell
php src/verify.php file [verbose]
```
Where:
- `file` is path to .XAdES file
- `verbose` if true print additional info about sign time and
- `load-content` - loads file content into variable and verifies it as embedded object (can not rely on files on disk)

Verifies content in given XAdES file, prints `OK` if everything passes, error message otherwise.

### Extracting file from XAdES files

```shell
php src/extract.php file output
```
Where:
- `file` is path to .XAdES file with embedded object
- `output` path for output file
