# cloudhsmtool

A CLI application that performs the follows functions on AWS CloudHSM:

* generate a non-extractable private key and a corresponding public key in the CloudHSM Keystore using `cloudhsmtool genrsa`.
* produce a self-signed X509 certificate from a public and private key in the CloudHSM Keystore, using `cloudhsmtool create-self-signed-cert`.
* produce a X509 certificate signed by another private key in the CloudHSM Keystore, using `cloudhsmtool create-chained-cert`.

### genrsa
This is a CLI to generate non-extractable Keys in the CloudHSM Keystore

Usage:
````
cloudhsmtool genrsa <a-key-label>
````
Generates a private key and a public key as separate entries in the CloudHSM Keystore.

For example. the entries in CloudHSM Keystore for the command
`cloudhsmtool genrsa foo` would be:

| Keystore Label | Keystore Entry |
|----------------|----------------|
| foo          | private key    |
| foo:public   | public key     |

Existing keys will not be overwritten.

The PEM-encoded public key will be emitted to `stdout`.

### create-self-signed-cert
Produces a self-signed X509 certificate from a public and private key in the CloudHSM Keystore.

Usage:
````
cloudhsmtool create-self-signed-cert <a-key-label> \
-C <country code> \
-L <location> \
-O <organization \
-OU <organizational unit> \
-CN <common name> \
-expiry <expiry in months as number>
````

This CLI emits a PEM-encoded X509 Certificate to `stdout`.

### create-chained-cert
Produces a X509 certificate signed by another private key in the CloudHSM Keystore.

Usage:
````
cloudhsmtool create-chained-cert <a-key-label> \
-C <country code> \
-L <location> \
-O <organization \
-OU <organizational unit> \
-CN <common name> \
-expiry <expiry in months as number> \
-parent-cert-base64 <PEM-encoded X509 Certificate> \
-parent-key-label <parent Keystore label> \
-ca-cert <set if an intermediate CA> 
````

This CLI emits a PEM-encoded X509 Certificate to `stdout`.

## Options

|               |               Description               | Required |     Default    |
|:-------------------:|:---------------------------------------:|:--------:|:--------------:|
| -C                  | Country Code                            | false    | GB             |
| -L                  | Location                                | false    | London         |
| -O                  | Organization                            | false    | Cabinet Office |
| -OU                 | Organizational Unit                     | false    | GDS            |
| -CN                 | Common Name                             | true     |                |
| -expiry             | Duration of certificate in months       | false    | 12             |
| -parent-cert-base64 | PEM encoded parent certificate, only for chained cert          | true     |                |
| -parent-key-label   | key label of parent RSA key, only for chained cert             | true     |                |
| -ca-cert            | Describes this certificate as a CA cert, only for chained cert | false    | false          |

## Running cloudhsmtool using docker

Build the docker image using the command:

```
docker build -t cloudhsmtool:docker .
```

Start the container with:

```
HSM_USER=<user> HSM_PASSWORD=<password> ./launch-docker.bash 
```

Where `<user>` and `<password>` are appropriate values.  Ask a
member of the helping users team if you need these values.

Once in the container you can use the alias `hsmtool` followed
by your chosen command and options.