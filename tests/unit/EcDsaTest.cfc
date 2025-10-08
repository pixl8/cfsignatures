component extends="testbox.system.BaseSpec" {

	function run() {
		var _svc    = new cfsignatures.models.algorithms.EcDsa();
		var _formatter = new cfsignatures.models.util.CertFormatter();

		describe( "generateKeys()", function() {
			it( "should generate a key pair using the algorithm to guide the size", function() {
				var key1 = _svc.generateKeys( "SHA256withECDSA" );
				var key2 = _svc.generateKeys( "SHA384withECDSA" );
				var key3 = _svc.generateKeys( "SHA512withECDSA" );

				expect( IsStruct( key1 ) ).toBeTrue();
				expect( StructKeyExists( key1, "publicKey" ) ).toBeTrue();
				expect( StructKeyExists( key1, "privateKey" ) ).toBeTrue();

				expect( key1.publicKey ).notToBe( key2.publicKey );
				expect( key1.privateKey ).notToBe( key2.privateKey );
				expect( key1.publicKey ).notToBe( key3.publicKey );
				expect( key1.privateKey ).notToBe( key3.privateKey );

				expect( ListLen( key1.publicKey, Chr( 10 ) ) ).toBe( 4 );
				expect( ListLen( key1.privateKey, Chr( 10 ) ) ).toBe( 4 );
				expect( ListFirst( key1.publicKey, Chr( 10 ) ) ).toBe( "-----BEGIN PUBLIC KEY-----" );
				expect( ListLast( key1.publicKey, Chr( 10 ) ) ).toBe( "-----END PUBLIC KEY-----" );
				expect( ListFirst( key1.privateKey, Chr( 10 ) ) ).toBe( "-----BEGIN PRIVATE KEY-----" );
				expect( ListLast( key1.privateKey, Chr( 10 ) ) ).toBe( "-----END PRIVATE KEY-----" );

				expect( ListLen( key2.publicKey, Chr( 10 ) ) ).toBe( 5 );
				expect( ListLen( key2.privateKey, Chr( 10 ) ) ).toBe( 4 );
				expect( ListFirst( key2.publicKey, Chr( 10 ) ) ).toBe( "-----BEGIN PUBLIC KEY-----" );
				expect( ListLast( key2.publicKey, Chr( 10 ) ) ).toBe( "-----END PUBLIC KEY-----" );
				expect( ListFirst( key2.privateKey, Chr( 10 ) ) ).toBe( "-----BEGIN PRIVATE KEY-----" );
				expect( ListLast( key2.privateKey, Chr( 10 ) ) ).toBe( "-----END PRIVATE KEY-----" );

				expect( ListLen( key3.publicKey, Chr( 10 ) ) ).toBe( 6 );
				expect( ListLen( key3.privateKey, Chr( 10 ) ) ).toBe( 5 );
				expect( ListFirst( key3.publicKey, Chr( 10 ) ) ).toBe( "-----BEGIN PUBLIC KEY-----" );
				expect( ListLast( key3.publicKey, Chr( 10 ) ) ).toBe( "-----END PUBLIC KEY-----" );
				expect( ListFirst( key3.privateKey, Chr( 10 ) ) ).toBe( "-----BEGIN PRIVATE KEY-----" );
				expect( ListLast( key3.privateKey, Chr( 10 ) ) ).toBe( "-----END PRIVATE KEY-----" );
			} );
		} );

		describe( "sign() + verify()", function() {
			it( "should sign and verify using SHA256withECDSA", function() {
				var keys    = _svc.generateKeys( "SHA256withECDSA" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = _formatter.getBase64EncodedPrivateKey( keys.privateKey ),
					algorithm  = "SHA256withECDSA"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBeBetween( 75, 100 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = _formatter.getBase64EncodedPublicKey( keys.publicKey )
					, payload      = payload
					, algorithm    = "SHA256withECDSA"
				) ).toBeTrue();
			} );

			it( "should sign and verify using SHA384withRSA", function() {
				var keys    = _svc.generateKeys( "SHA384withECDSA" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = _formatter.getBase64EncodedPrivateKey( keys.privateKey ),
					algorithm  = "SHA384withECDSA"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBeBetween( 120, 140 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = _formatter.getBase64EncodedPublicKey( keys.publicKey )
					, payload      = payload
					, algorithm    = "SHA384withECDSA"
				) ).toBeTrue();
			} );

			it( "should sign and verify using SHA512withRSA", function() {
				var keys    = _svc.generateKeys( "SHA512withECDSA" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = _formatter.getBase64EncodedPrivateKey( keys.privateKey ),
					algorithm  = "SHA512withECDSA"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBeBetween( 170, 180 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = _formatter.getBase64EncodedPublicKey( keys.publicKey )
					, payload      = payload
					, algorithm    = "SHA512withECDSA"
				) ).toBeTrue();
			} );
		} );

		describe( "validateSigningKey()", function() {
			it( "should validate a signing key for SHA256withECDSA", function() {
				var key = _svc.generateKeys( "SHA256withECDSA" );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA256withECDSA" ) ).toBeTrue();
			} );

			it( "should validate a signing key for SHA384withECDSA", function() {
				var key = _svc.generateKeys( "SHA384withECDSA" );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA384withECDSA" ) ).toBeTrue();
			} );

			it( "should validate a signing key for SHA512withECDSA", function() {
				var key = _svc.generateKeys( "SHA512withECDSA" );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA512withECDSA" ) ).toBeTrue();
			} );

			it( "should return false for something completely different", function() {
				var key = "not a base64 representation of a char array that will be a valid cert";
				expect( _svc.validateSigningKey( key, "SHA256withECDSA" ) ).toBeFalse();
				expect( _svc.validateSigningKey( key, "SHA384withECDSA" ) ).toBeFalse();
				expect( _svc.validateSigningKey( key, "SHA512withECDSA" ) ).toBeFalse();
			} );

			it( "should return false when key is for a different algorithm than the one provided", function() {
				var key = _svc.generateKeys( "SHA256withECDSA" );

				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA384withECDSA" ) ).toBeFalse();
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA512withECDSA" ) ).toBeFalse();

				key = _svc.generateKeys( "SHA384withECDSA" );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA256withECDSA" ) ).toBeFalse();
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA512withECDSA" ) ).toBeFalse();

				key = _svc.generateKeys( "SHA512withECDSA" );
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA256withECDSA" ) ).toBeFalse();
				expect( _svc.validateSigningKey( _formatter.getBase64EncodedPrivateKey( key.privateKey ), "SHA384withECDSA" ) ).toBeFalse();
			} );

		} );

		describe( "validateVerifyingKey()", function() {
			it( "should validate a verifying key for SHA256withECDSA", function() {
				var key = _svc.generateKeys( "SHA256withECDSA" );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA256withECDSA" ) ).toBeTrue();
			} );

			it( "should validate a verifying key for SHA384withECDSA", function() {
				var key = _svc.generateKeys( "SHA384withECDSA" );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA384withECDSA" ) ).toBeTrue();
			} );

			it( "should validate a verifying key for SHA512withECDSA", function() {
				var key = _svc.generateKeys( "SHA512withECDSA" );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA512withECDSA" ) ).toBeTrue();
			} );

			it( "should return false for something completely different", function() {
				var key = "not a base64 representation of a char array that will be a valid cert";
				expect( _svc.validateVerifyingKey( key, "SHA256withECDSA" ) ).toBeFalse();
				expect( _svc.validateVerifyingKey( key, "SHA384withECDSA" ) ).toBeFalse();
				expect( _svc.validateVerifyingKey( key, "SHA512withECDSA" ) ).toBeFalse();
			} );

			it( "should return false when key is for a different algorithm than the one provided", function() {
				var key = _svc.generateKeys( "SHA256withECDSA" );

				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA384withECDSA" ) ).toBeFalse();
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA512withECDSA" ) ).toBeFalse();

				key = _svc.generateKeys( "SHA384withECDSA" );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA256withECDSA" ) ).toBeFalse();
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA512withECDSA" ) ).toBeFalse();

				key = _svc.generateKeys( "SHA512withECDSA" );
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA256withECDSA" ) ).toBeFalse();
				expect( _svc.validateVerifyingKey( _formatter.getBase64EncodedPublicKey( key.publicKey ), "SHA384withECDSA" ) ).toBeFalse();
			} );
		} );
	}

}