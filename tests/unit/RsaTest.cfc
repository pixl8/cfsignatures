component extends="testbox.system.BaseSpec" {

	function run() {
		var _svc = new cfsignatures.models.algorithms.Rsa();
		var _formatter = new cfsignatures.models.util.CertFormatter();

		describe( "generateKeys()", function() {
			it( "should generate a key pair using the default input size as a guide", function() {
				var key1 = _svc.generateKeys( "SHA256withRSA" );
				var key2 = _svc.generateKeys( "SHA256withRSA" );

				expect( IsStruct( key1 ) ).toBeTrue();
				expect( StructKeyExists( key1, "publicKey" ) ).toBeTrue();
				expect( StructKeyExists( key1, "privateKey" ) ).toBeTrue();

				expect( key1.publicKey ).notToBe( key2.publicKey );
				expect( key1.privateKey ).notToBe( key2.privateKey );

				expect( ListLen( key1.publicKey, Chr( 10 ) ) ).toBe( 9 );
				expect( ListLen( key1.privateKey, Chr( 10 ) ) ).toBe( 28 );
				expect( ListFirst( key1.publicKey, Chr( 10 ) ) ).toBe( "-----BEGIN PUBLIC KEY-----" );
				expect( ListLast( key1.publicKey, Chr( 10 ) ) ).toBe( "-----END PUBLIC KEY-----" );
				expect( ListFirst( key1.privateKey, Chr( 10 ) ) ).toBe( "-----BEGIN PRIVATE KEY-----" );
				expect( ListLast( key1.privateKey, Chr( 10 ) ) ).toBe( "-----END PRIVATE KEY-----" );
			} );

			it( "should generate a key pair using the default input size as a guide", function() {
				var key1 = _svc.generateKeys( algorithm="SHA256withRSA", size=4096 );

				expect( IsStruct( key1 ) ).toBeTrue();
				expect( StructKeyExists( key1, "publicKey" ) ).toBeTrue();
				expect( StructKeyExists( key1, "privateKey" ) ).toBeTrue();

				expect( ListLen( key1.publicKey, Chr( 10 ) ) ).toBe( 14 );
				expect( ListLen( key1.privateKey, Chr( 10 ) ) ).toBe( 52 );
				expect( ListFirst( key1.publicKey, Chr( 10 ) ) ).toBe( "-----BEGIN PUBLIC KEY-----" );
				expect( ListLast( key1.publicKey, Chr( 10 ) ) ).toBe( "-----END PUBLIC KEY-----" );
				expect( ListFirst( key1.privateKey, Chr( 10 ) ) ).toBe( "-----BEGIN PRIVATE KEY-----" );
				expect( ListLast( key1.privateKey, Chr( 10 ) ) ).toBe( "-----END PRIVATE KEY-----" );
			} );
		} );

		describe( "sign() + verify()", function() {
			it( "should sign and verify using SHA256withRSA", function() {
				var keys    = _svc.generateKeys( "SHA256withRSA" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = _formatter.getBase64EncodedPrivateKey( keys.privateKey ),
					algorithm  = "SHA256withRSA"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBe( 342 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = _formatter.getBase64EncodedPublicKey( keys.publicKey )
					, payload      = payload
					, algorithm    = "SHA256withRSA"
				) ).toBeTrue();
			} );

			it( "should sign and verify using SHA384withRSA", function() {
				var keys    = _svc.generateKeys( "SHA384withRSA" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = _formatter.getBase64EncodedPrivateKey( keys.privateKey ),
					algorithm  = "SHA384withRSA"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBe( 342 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = _formatter.getBase64EncodedPublicKey( keys.publicKey )
					, payload      = payload
					, algorithm    = "SHA384withRSA"
				) ).toBeTrue();
			} );

			it( "should sign and verify using SHA512withRSA", function() {
				var keys    = _svc.generateKeys( "SHA512withRSA" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = _formatter.getBase64EncodedPrivateKey( keys.privateKey ),
					algorithm  = "SHA512withRSA"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBe( 342 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = _formatter.getBase64EncodedPublicKey( keys.publicKey )
					, payload      = payload
					, algorithm    = "SHA512withRSA"
				) ).toBeTrue();
			} );
		} );

		describe( "validateSigningKey()", function() {
			it( "should validate that the key is be a valid RSA private key", function() {
				var key = _svc.generateKeys( "SHA256withRSA", 1024 );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ) ) ).toBeTrue();
				key = _svc.generateKeys( "SHA256withRSA", 2048 );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ) ) ).toBeTrue();
				key = _svc.generateKeys( "SHA256withRSA", 4096 );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ) ) ).toBeTrue();
			} );

			it( "should return false for RSA public keys", function() {
				var key = _svc.generateKeys( "SHA384withRSA", 1024 );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA384withRSA" ) ).toBeFalse();
				key = _svc.generateKeys( "SHA384withRSA", 2048 );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA384withRSA" ) ).toBeFalse();
				key = _svc.generateKeys( "SHA384withRSA", 4096 );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA384withRSA" ) ).toBeFalse();
			} );

			it( "should return false for something completely different", function() {
				var key = "not a base64 representation of a char array that will be a valid cert";
				expect( _svc.validateSigningKey( key ) ).toBeFalse();
			} );
		} );

		describe( "validateVerifyingKey()", function() {
			it( "should validate that the key is a valid RSA public key", function() {
				var key = _svc.generateKeys( "SHA256withRSA", 1024 );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ) ) ).toBeTrue();
				key = _svc.generateKeys( "SHA256withRSA", 2048 );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ) ) ).toBeTrue();
				key = _svc.generateKeys( "SHA256withRSA", 4096 );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ) ) ).toBeTrue();
			} );

			it( "should return false for RSA private keys", function() {
				var key = _svc.generateKeys( "SHA384withRSA", 1024 );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ) ) ).toBeFalse();
				key = _svc.generateKeys( "SHA384withRSA", 2048 );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ) ) ).toBeFalse();
				key = _svc.generateKeys( "SHA384withRSA", 4096 );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ) ) ).toBeFalse();
			} );

			it( "should return false for something completely different", function() {
				var key = "not a base64 representation of a char array that will be a valid cert";
				expect( _svc.validateVerifyingKey( key ) ).toBeFalse();
			} );
		} );
	}
}