# USAGE

```
php src/sign.php file cert pass [embed]
```
Where:
- `file` - path to file we want to sign. Signature will be created in the same folder, with .XAdES extension
- `cert` - certificate in PKCS#12 format (.p12) - with private key
- `pass` - password for p12 file
- `embed` - if true, signature will embed given file

```
php src/verify.php file [verbose]
```
Where:
- `file` is path to .XAdES file
- `verbose` if true print additional info