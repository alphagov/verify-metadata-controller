# CLoudHSM tool

## Overview

A set of command line interface (CLI) Java applications that integrate with Amazon CloudHSM to:

* generate non-extractable keys in the CloudHSM Keystore
* produce a self-signed certificate from keys in the CloudHSM Keystore
* generate a certificate chained to a signature from another key in the CloudHSM Keystore

The `metadata-controller` will execute these CLIs.

### genrsa
This is a CLI to generate non-extractable Keys in the CloudHSM Keystore

Usage:
````bash
genrsa <a-key-label>
````
Generates a Private Key and a Public Key as separate entries in the CloudHSM Keystore.
The aliases of these CloudHSM Keystore entries will be:

| Keystore Alias | Keystore Entry |
|----------------|----------------|
| label          | private key    |
| label:public   | public key     |

Existing keys will not be overwritten.

The PEM-encoded Public Key will be emitted to `stdout`.

### create-self-signed-cert
Produces a self-signed certificate from Keys in the CloudHSM Keystore

Usage:
````bash
create-self-signed-cert <a-key-label> \
-C <country code> \
-L <location> \
-O <organization \
-OU <organizational unit> \
-CN <common name> \
-expiry <expiry in months as number>
````

This CLI emits a PEM-encoded X509 Certificate to `stdout`.

### create-chained-cert
Produces a self-signed certificate from Keys in the CloudHSM Keystore

Usage:
````bash
create-chained-cert <a-key-label> \
-C <country code> \
-L <location> \
-O <organization \
-OU <organizational unit> \
-CN <common name> \
-expiry <expiry in months as number> \
-parent-cert-base64 <PEM-encoded X509 Certificate> \
-parent-key-label <parent Keystore label> \
-ca-cert <true if an intermediate CA> 
````

This CLI emits a PEM-encoded X509 Certificate to `stdout`.