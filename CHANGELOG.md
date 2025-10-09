# Changelog

## v1.1.1

* Fix hmac key validation logic.

## v1.1.0

* Add `validateSigningKey( key, algorithm )` method for validating incoming signing keys
* Add `validateVerifyingKey( key, algorithm )` method for validating incoming verification keys

## v1.0.0

Initial publication with features:

* Generating signing and verification keys
* Generating signatures
* Verifying signatures

Supported algorithms:

* HS256
* HS384
* HS512
* RS256
* RS384
* RS512
* ES256
* ES384
* ES512


