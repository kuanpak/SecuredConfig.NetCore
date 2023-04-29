# SecuredConfig encryption and decryption tool

## Encrypt the given string by the given certificate.

### Usage:
```
secured-config encrypt [options]
```

#### Options:
*  `-c, --cert <cert> (REQUIRED)      The certificate file to encrypt the configuration value.`
*  `-p, --password <password>         The password of the certificate.`
*  `-s, --string <string> (REQUIRED)  The string value to be encrypted.`
*  `-?, -h, --help                    Show help and usage information`


---

## Decrypt the given encrypted string by the given PFX certificate.

### Usage:
```
secured-config decrypt [options]
```

#### Options:
*  `-c, --cert <cert> (REQUIRED)                          The certificate file to encrypt the configuration value.`
*  `-p, --password <password>                             The password of the certificate.`
*  `-e, --encrypted-string <encrypted-string> (REQUIRED)  The string value to be decrypted.`
*  `-?, -h, --help                                        Show help and usage information`