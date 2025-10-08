/**
 * CfSignatures is a component that provides a pair of methods for creating and verifying signatures.
 * It is a wrapper around the algorithms and helpers components and provides a consistent interface for
 * signing and verifying signatures using the following algorithms:
 *
 * - ES256: ECDSA with SHA-256
 * - ES384: ECDSA with SHA-384
 * - ES512: ECDSA with SHA-512
 * - RS256: RSA with SHA-256
 * - RS384: RSA with SHA-384
 * - RS512: RSA with SHA-512
 * - HS256: HMAC with SHA-256
 * - HS384: HMAC with SHA-384
 * - HS512: HMAC with SHA-512
 *
 * @singleton
 */
component {

	variables._services = {
		  es   = new algorithms.EcDsa()
		, rs   = new algorithms.Rsa()
		, hs   = new algorithms.Hmac()
		, cert = new util.CertFormatter()
	};
	variables._supportedAlgorithms = {
		  ES256 = "SHA256withECDSA"
		, ES384 = "SHA384withECDSA"
		, ES512 = "SHA512withECDSA"
		, RS256 = "SHA256withRSA"
		, RS384 = "SHA384withRSA"
		, RS512 = "SHA512withRSA"
		, HS256 = "HmacSHA256"
		, HS384 = "HmacSHA384"
		, HS512 = "HmacSHA512"
	};

	/**
	 * Returns a base64 encoded signature for the given payload, signing key and algorithm.
	 *
	 * @payload.hint    String payload to sign. for example, the header and payload of a JWT.
	 * @signingKey.hint Either the shared secret key for the HMAC algorithm or the PRIVATE key for the RSA/ES algorithms.
	 * @algorithm.hint  Algorithm to use for signing. Supported algorithms are: ES256, ES384, ES512, RS256, RS384, RS512, HS256, HS384, HS512.
	 */
	function sign(
		  required string payload
		, required string signingKey
		, required string algorithm
	) {
		var algo = _getAlgorithm( arguments.algorithm );

		return _services[ Left( arguments.algorithm, 2 ) ].sign(
			  payload    = arguments.payload
			, signingKey = _services.cert.getBase64EncodedPrivateKey( arguments.signingKey )
			, algorithm  = algo
		);
	}

	/**
	 * Verifies a signature for the given payload, verifying key and algorithm.
	 * Returns true if the signature is valid, false otherwise.
	 *
	 * @signature.hint    Base64 encoded signature to verify.
	 * @verifyingKey.hint Either the shared secret key for the HMAC algorithm or the PUBLIC key for the RSA/ES algorithms.
	 * @payload.hint      String payload to verify. for example, the header and payload of a JWT.
	 * @algorithm.hint    Algorithm to use for verifying. Supported algorithms are: ES256, ES384, ES512, RS256, RS384, RS512, HS256, HS384, HS512.
	 */
	function verify(
		  required string signature
		, required string verifyingKey
		, required string payload
		, required string algorithm
	) {
		var algo = _getAlgorithm( arguments.algorithm );

		return _services[ Left( arguments.algorithm, 2 ) ].verify(
			  signature    = arguments.signature
			, verifyingKey = _services.cert.getBase64EncodedPublicKey( arguments.verifyingKey )
			, payload      = arguments.payload
			, algorithm    = _getAlgorithm( arguments.algorithm )
		);
	}

	/**
	 * Generates signging keys for the given algorithm. Return type may vary depending on the algorithm.
	 * For synchronous algorithms (HMAC), returned value will be a plain string, this is the base64 encoded key.
	 * For asynchronous algorithms (RSA/ES), returned value will be a struct with the public and private keys in PEM format.
	 *
	 * @algorithm.hint Algorithm to use for generating the key(s). Supported algorithms are: ES256, ES384, ES512, RS256, RS384, RS512, HS256, HS384, HS512.
	 * @size.hint      Size of the key pair to generate (for RSA keys only)
	 */
	function generateKeys( required string algorithm, numeric size ) {
		var algo = _getAlgorithm( arguments.algorithm );

		return _services[ Left( arguments.algorithm, 2 ) ].generateKeys( algorithm = algo, argumentCollection=arguments );
	}

	/**
	 * Validates a signing key for the given algorithm.
	 * Returns true if the key is valid, false otherwise.
	 *
	 * @key.hint       Base64 encoded signing key.
	 * @algorithm.hint Algorithm to use for validating the key. Supported algorithms are: ES256, ES384, ES512, RS256, RS384, RS512, HS256, HS384, HS512.
	 */
	function validateSigningKey( required string key, required string algorithm ) {
		var algo         = _getAlgorithm( arguments.algorithm );
		var formattedKey = _services.cert.getBase64EncodedPrivateKey( arguments.key );

		return _services[ Left( arguments.algorithm, 2 ) ].validateSigningKey( formattedKey, algo );
	}

	/**
	 * Validates a verifying key for the given algorithm.
	 * Returns true if the key is valid, false otherwise.
	 *
	 * @key.hint       Base64 encoded verifying key.
	 * @algorithm.hint Algorithm to use for validating the key. Supported algorithms are: ES256, ES384, ES512, RS256, RS384, RS512, HS256, HS384, HS512.
	 */
	function validateVerifyingKey( required string key, required string algorithm ) {
		var algo         = _getAlgorithm( arguments.algorithm );
		var formattedKey = _services.cert.getBase64EncodedPublicKey( arguments.key );

		return _services[ Left( arguments.algorithm, 2 ) ].validateVerifyingKey( formattedKey, algo );
	}

// PRIVATE HELPERS
	private function _getAlgorithm( required string algorithm ) {
		if ( !variables._supportedAlgorithms.keyExists( arguments.algorithm ) ) {
			throw( type="invalid.algorithm", message="Invalid algorithm: [#arguments.algorithm#]. Supported algorithms: [#StructKeyList( variables._supportedAlgorithms, ', ' )#]" );
		}

		return variables._supportedAlgorithms[ arguments.algorithm ];
	}

}