/**
 * RSA algorithm is a cryptographic algorithm that uses the RSA cryptosystem to sign and verify messages.
 * It is a variant of the DSA algorithm and is considered more secure than the DSA and HMAC algorithms because
 * it uses a larger key size.
 */
component {

	function init(){
		variables.keyFactory = CreateObject( "java", "java.security.KeyFactory" ).getInstance( "RSA" );
	}

// PUBLIC METHODS
	public string function sign(
		  required string payload
		, required string signingKey
		, required string algorithm
	) {
		var privateKey     = _getPrivateKey( arguments.signingKey );
		var signer         = _getSigner( arguments.algorithm, privateKey, arguments.payload );
		var signatureBytes = signer.sign();

		return _formatSignature( signatureBytes );
	}

	public boolean function verify(
		  required string signature
		, required string verifyingKey
		, required string payload
		, required string algorithm
	) {
		var publicKey = _getPublicKey( arguments.verifyingKey );
		var verifier  = _getVerifier( arguments.algorithm, publicKey, arguments.payload );
		var sigBytes  = _convertSignatureToByteArray( arguments.signature );

		return verifier.verify( sigBytes );
	}

	function generateKeys( required string algorithm, numeric size=2048 ) {
		var keyPairGenerator = CreateObject("java", "java.security.KeyPairGenerator").getInstance( "RSA" );
		keyPairGenerator.initialize( arguments.size );

		var keyPair = keyPairGenerator.generateKeyPair();

		return {
			  privateKey = _toPem( keyPair.getPrivate().getEncoded(), "PRIVATE KEY" )
			, publicKey  = _toPem( keyPair.getPublic().getEncoded(), "PUBLIC KEY" )
		};
	}

	public boolean function validateSigningKey( required string key ) {
		try {
			return isInstanceOf( _getPrivateKey( arguments.key ), "java.security.PrivateKey" );
		} catch( any e ) {}

		return false;
	}

	public boolean function validateVerifyingKey( required string key ) {
		try {
			return isInstanceOf( _getPublicKey( arguments.key ), "java.security.PublicKey" );
		} catch( any e ) {}

		return false;
	}

// PRIVATE HELPERS
	private function _base64UrlEscape( value ){
		return ReReplace( ReReplace( ReReplace( arguments.value, "\+", "-", "all" ), "\/", "_", "all" ) ,"=", "", "all" )
	}

	private function _getPublicKey( verifyingKey ){
		var key = CreateObject( "java", "java.security.spec.X509EncodedKeySpec" ).init( toBinary( arguments.verifyingKey ) );

		return variables.keyFactory.generatePublic( key );
	}

	private function _getPrivateKey( signingKey ){
		var key = CreateObject( "java", "java.security.spec.PKCS8EncodedKeySpec" ).init( toBinary( arguments.signingKey ) );

		return variables.keyFactory.generatePrivate( key );
	}

	private function _getSigner( algorithm, privateKey, payload ){
		var signer = CreateObject( "java", "java.security.Signature" ).getInstance( arguments.algorithm );

		signer.initSign( arguments.privateKey );
		signer.update( arguments.payload.getBytes() );

		return signer;
	}

	private function _getVerifier( algorithm, publicKey, payload ){
		var verifier = CreateObject( "java", "java.security.Signature" ).getInstance( arguments.algorithm );

		verifier.initVerify( arguments.publicKey );
		verifier.update( arguments.payload.getBytes() );

		return verifier;
	}

	private function _convertSignatureToByteArray( signature ){
		return CreateObject( "java", "java.util.Base64" ).getUrlDecoder().decode( arguments.signature );
	}

	private function _formatSignature( signatureBytes ){
		var signature = CreateObject( "java", "java.util.Base64" ).getUrlEncoder().withoutPadding().encodeToString( signatureBytes );

		return _base64UrlEscape( signature );
	}

	private function _toPem( rawKey, type ){
		var base64Encoder = CreateObject( "java", "java.util.Base64" ).getEncoder();
		var base64String  = base64Encoder.encodeToString( arguments.rawKey );
		var pem           = "-----BEGIN " & arguments.type & "-----#chr(10)#";

		for ( var i=1; i<=Len( base64String ); i+=64 ) {
			pem &= Mid( base64String, i, 64 ) & chr(10);
		}
		pem &= "-----END " & arguments.type & "-----";

		return pem;
	}
}