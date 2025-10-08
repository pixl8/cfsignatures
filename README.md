# cfsignatures: Simple cryptographic signature verification and generation for CFML

[![On Forgebox](https://forgebox.io/api/v1/entry/cfsignatures/badges/version)](https://forgebox.io/view/cfsignatures)


This extension provides a simple API for verifying and generating cryptographic signatures. Useful in various
operations where signatures are used such as [JWT](https://www.rfc-editor.org/rfc/rfc7519)

## Usage

### General

You use this project by getting a singleton instance of the `CfSignatures` object (see ColdBox and Non-Coldbox sections below). Then calling its methods:

* `sign( payload, signingKey, algorithm )` returns a base64 encoded signature for the string payload using the provided signing key and algorithm.
* `verify( signature, payload, verifyingKey, algorithm )` returns true if the signature is valid for the given payload, verifyingKey and algorithm, false otherwise.
* `generateKeys( algorithm )`: For HS* algorithm, returns a new base64 encoded shared secret key. For RS* ES* algorithm, returns a struct with `privateKey` and `publicKey` in PEM format
* `validateSigningKey( key, algorithm )` returns true if the provided base64 or PEM encoded signing key is valid for the provided algorithm.
* `validateVerifyingKey( key, algorithm )` returns true if the provided base64 or PEM encoded verification key is valid for the provided algorithm.

**Note for RS + ES algorithms**: these are asynchronous algorithms that use a private and public key pair. The private key is always used for _signing_. The public key is always used for _verification_.

### Coldbox

This utility is wrapped up as a Coldbox module for those using Coldbox. Install into your application or module and then:

```cfc
property name="cfsignatures" inject="cfsignatures@cfsignatures";
```

### Non-Coldbox

Install into your project under whatever root directory you wish and create a mapping `/cfsignatures` pointing
at the install location. Then:

```cfc
var cfsignatures = new cfsignatures.models.CfSignatures();

// or if you are using a DI framework, you can register the above component for injection.
```

## Supported algorithms

### Hmac

Synchronous signing. This means that your signingKey and verifiyingKey will be the same. This is the most straight forward
signature algorithm due to this. Always use a base64 encoded key for signging and verifying.

* HS256
* HS384
* HS512

### RSA

Ansynchronous signing using public and private key pairs. The private key must be used for generating signatures and the
public key used for verifying signatures.

* RS256
* RS384
* RS512

You can and should enter PEM formatted certificates for signing and verifying (which you can generate with the `generateKeys()` method). Alternatively, you can pass the base64 encoded key without line breaks.


### ECDSA

Ansynchronous signing using public and private key pairs. The private key must be used for generating signatures and the
public key used for verifying signatures.

* ES256
* ES384
* ES512

You can and should enter PEM formatted certificates for signing and verifying (which you can generate with the `generateKeys()` method). Alternatively, you can pass the base64 encoded key without line breaks.

## Versioning

We use [SemVer](https://semver.org) for versioning. For the versions available, see the [tags on this repository](https://github.com/pixl8/cfsignatures/releases). Project releases can also be found and installed from [Forgebox](https://forgebox.io/view/cfsignatures).

## Get involved

Contribution is very welcome. You can get involved by:

* Raising issues in [Github](https://github.com/pixl8/cfsignatures), both ideas and bugs welcome
* Creating pull requests in [Github](https://github.com/pixl8/cfsignatures)

## License

This project is licensed under the GPLv2 License - see the [LICENSE.txt](https://github.com/pixl8/cfsignatures/blob/stable/LICENSE.txt) file for details.

## Authors

The project is maintained by [The Pixl8 Group](https://www.pixl8.co.uk). The lead developer is [Dominic Watson](https://github.com/DominicWatson).

## Code of conduct

We are a small, friendly and professional community. For the eradication of doubt, we publish a simple [code of conduct](https://github.com/pixl8/cfsignatures/blob/stable/CODE_OF_CONDUCT.md) and expect all contributors, users and passers-by to observe it.