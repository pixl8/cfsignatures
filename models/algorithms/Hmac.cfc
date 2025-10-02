/**
 * Hmac algorithm is a synchronous signing algorithm using a share secret key.
 * It is the most straight forward algorithm to implement and is suitable for most use cases.
 * It is also considered less secure than other algorithms such as RSA and ECDSA because
 * leaking of the secret key can allow an attacker to sign messages with the same key.
 */
component {

// PUBLIC METHODS
	public function sign(
		  required string payload
		, required string signingKey
		, required string algorithm
	) {
		var key = CreateObject( "java", "javax.crypto.spec.SecretKeySpec" ).init( toBinary( arguments.signingKey ), arguments.algorithm );
		var mac = CreateObject( "java", "javax.crypto.Mac" ).getInstance( arguments.algorithm );

		mac.init( key );

		return _base64UrlEscape( ToBase64( mac.doFinal( arguments.payload.getBytes() ) ) );
	}

	function verify(
		  required string signature
		, required string verifyingKey
		, required string payload
		, required string algorithm
	) {
		return sign(
			  payload    = arguments.payload
			, signingKey = arguments.verifyingKey
			, algorithm  = arguments.algorithm
		) == arguments.signature;
	}

	function generateKeys( required string algorithm ) {
		var keyGen = CreateObject("java", "javax.crypto.KeyGenerator").getInstance( arguments.algorithm );
		switch ( arguments.algorithm ) {
			case "HmacSHA256":
				keyGen.init( 256 );
			break;
			case "HmacSHA384":
				keyGen.init(384);
			break;
			case "HmacSHA512":
				keyGen.init(512);
			break;
		}

		return ToBase64( keyGen.generateKey().getEncoded() );
	}

// PRIVATE HELPERS
	private function _base64UrlEscape( required string value ){
		return ReReplace( ReReplace( ReReplace( arguments.value, "\+", "-", "all" ), "\/", "_", "all" ) ,"=", "", "all" )
	}
}