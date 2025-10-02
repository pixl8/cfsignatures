component extends="testbox.system.BaseSpec" {

	function run() {
		var _svc = new cfsignatures.models.algorithms.Hmac();

		describe( "generateKeys()", function() {
			it( "should generate a suitably sized random key for HmacSHA256", function() {
				var key1 = _svc.generateKeys( "HmacSHA256" );
				var key2 = _svc.generateKeys( "HmacSHA256" );

				expect( key1 ).notToBe( key2 );
				expect( Len( key1 ) ).toBe( 44 );
				expect( Len( key2 ) ).toBe( 44 );
			} );

			it( "should generate a suitably sized random key for HmacSHA512", function() {
				var key1 = _svc.generateKeys( "HmacSHA384" );
				var key2 = _svc.generateKeys( "HmacSHA384" );

				expect( key1 ).notToBe( key2 );
				expect( Len( key1 ) ).toBe( 64 );
				expect( Len( key2 ) ).toBe( 64 );
			} );

			it( "should generate a suitably sized random key for HmacSHA512", function() {
				var key1 = _svc.generateKeys( "HmacSHA512" );
				var key2 = _svc.generateKeys( "HmacSHA512" );

				expect( key1 ).notToBe( key2 );
				expect( Len( key1 ) ).toBe( 88 );
				expect( Len( key2 ) ).toBe( 88 );
			} );
		} );

		describe( "sign() + verify()", function() {
			it( "should sign and verify using HmacSHA256", function() {
				var key     = _svc.generateKeys( "HmacSHA256" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = key,
					algorithm  = "HmacSHA256"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBe( 43 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = key
					, payload      = payload
					, algorithm    = "HmacSHA256"
				) ).toBeTrue();
			} );

			it( "should sign and verify using HmacSHA384", function() {
				var key     = _svc.generateKeys( "HmacSHA384" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = key,
					algorithm  = "HmacSHA384"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBe( 64 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = key
					, payload      = payload
					, algorithm    = "HmacSHA384"
				) ).toBeTrue();
			} );

			it( "should sign and verify using HmacSHA512", function() {
				var key     = _svc.generateKeys( "HmacSHA512" );
				var payload = CreateUUId();
				var signature = _svc.sign(
					payload    = payload,
					signingKey = key,
					algorithm  = "HmacSHA512"
				);

				expect( signature ).toBeString();
				expect( Len( signature ) ).toBe( 86 );

				expect( _svc.verify(
					  signature    = signature
					, verifyingKey = key
					, payload      = payload
					, algorithm    = "HmacSHA512"
				) ).toBeTrue();
			} );
		} );
	}
}