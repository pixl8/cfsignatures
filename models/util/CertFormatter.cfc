component {

	public string function getBase64EncodedPublicKey( required string cert ) {
		var formatted = ReReplace( Trim( arguments.cert ), "^-----BEGIN( RSA|ESA|ECDSA)? PUBLIC KEY-----", "", "all" );
		formatted = ReReplace( formatted, "-----END( RSA|ESA|ECDSA)? PUBLIC KEY-----$", "", "all" );

		return Trim( ReReplace( formatted, "\n", "", "all" ) );
	}

	public string function getBase64EncodedPrivateKey( required string key ) {
		var formatted = ReReplace( Trim( arguments.key ), "^-----BEGIN( RSA|ESA|ECDSA)? PRIVATE KEY-----", "", "all" );
		formatted = ReReplace( formatted, "-----END( RSA|ESA|ECDSA)? PRIVATE KEY-----$", "", "all" );

		return Trim( ReReplace( formatted, "\n", "", "all" ) );
	}
}
