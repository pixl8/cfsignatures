component extends="testbox.system.BaseSpec" {

	function run() {
		var _svc = new cfsignatures.models.CfSignatures();

		describe( "generateKeys()", function() {
			it( "should generate keys based on the algorithm", function() {
				var key1 = _svc.generateKeys( "RS256" );
				var key2 = _svc.generateKeys( "ES512" );
				var key3 = _svc.generateKeys( "HS384" );

				expect( IsStruct( key1 ) ).toBeTrue();
				expect( StructKeyExists( key1, "publicKey" ) ).toBeTrue();
				expect( StructKeyExists( key1, "privateKey" ) ).toBeTrue();

				expect( IsStruct( key2 ) ).toBeTrue();
				expect( StructKeyExists( key2, "publicKey" ) ).toBeTrue();
				expect( StructKeyExists( key2, "privateKey" ) ).toBeTrue();

				expect( key3 ).toBeString();
				expect( Len( key3 ) ).toBe( 64 );
			} );

			it( "should throw an error if the algorithm is not supported", function() {
				expect( function() {
					_svc.generateKeys( "blah" );
				} ).toThrow( "invalid.algorithm" );
			} );
		} );

		describe( "sign()", function() {
			it( "should raise an error if the algorithm is not supported", function() {
				expect( function() {
					_svc.sign(
						payload    = "blah",
						signingKey = "blah",
						algorithm  = "blah"
					);
				} ).toThrow( "invalid.algorithm" );
			} );
		} );

		describe( "verify()", function() {
			it( "should raise an error if the algorithm is not supported", function() {
				expect( function() {
					_svc.verify(
						signature    = "blah",
						payload    = "blah",
						verifyingKey = "blah",
						algorithm  = "blah"
					);
				} ).toThrow( "invalid.algorithm" );
			} );
		} );

		describe( "sign() + verify()", function() {
			it( "should sign and verify using all our supported algorithms", function() {
				var algorithms = [ "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512" ];

				for( var algorithm in algorithms ) {
					var keys    = _svc.generateKeys( algorithm );
					var privKey = IsSimpleValue( keys ) ? keys : keys.privateKey;
					var pubKey  = IsSimpleValue( keys ) ? keys : keys.publicKey;
					var payload = CreateUUId();
					var signature = _svc.sign(
						payload    = payload,
						signingKey = privKey,
						algorithm  = algorithm
					);
					expect( _svc.verify(
						signature    = signature,
						payload      = payload,
						verifyingKey = pubKey,
						algorithm    = algorithm
					) ).toBeTrue();
				}
			} );
		} );
	}
}