component {

	public string function getBase64EncodedPublicKey( required string cert ) {
		var formatted = ReReplace( Trim( arguments.cert ), "^-----BEGIN PUBLIC KEY-----", "", "all" );
		formatted = ReReplace( formatted, "-----END PUBLIC KEY-----$", "", "all" );

		return Trim( ReReplace( formatted, "\n", "", "all" ) );
	}

	public string function getBase64EncodedPrivateKey( required string key ) {
		var formatted = ReReplace( Trim( arguments.key ), "^-----BEGIN PRIVATE KEY-----", "", "all" );
		formatted = ReReplace( formatted, "-----END PRIVATE KEY-----$", "", "all" );

		return Trim( ReReplace( formatted, "\n", "", "all" ) );
	}
}
