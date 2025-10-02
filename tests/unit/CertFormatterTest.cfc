component extends="testbox.system.BaseSpec" {

	function run() {
		var _svc = new cfsignatures.models.util.CertFormatter();

		describe( "getBase64EncodedPublicKey()", function() {
			it( "should strip a formatted key and return the bare bones", function() {
				var fullKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnQwOizOiG
Jz7ZGk92eqHm5b1Bg8ZgopSls/csLRYB9sFevfumWNTpmgSN+GWX
Qbo3wL6Jla+uRce07zif6HknPzWC0moGoAqh+ETs/3j9q2sY
FKIUv7lAcOpvi8Xg8lqljfM2FjViKh+p5BSYD/l6E8LL
-----END PUBLIC KEY-----";

				var base64Key = _svc.getBase64EncodedPublicKey( fullKey );

				expect( base64Key ).toBe( "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsnQwOizOiGJz7ZGk92eqHm5b1Bg8ZgopSls/csLRYB9sFevfumWNTpmgSN+GWXQbo3wL6Jla+uRce07zif6HknPzWC0moGoAqh+ETs/3j9q2sYFKIUv7lAcOpvi8Xg8lqljfM2FjViKh+p5BSYD/l6E8LL" );
			} );
		});

		describe( "getBase64EncodedPrivateKey()", function() {
			it( "should strip a formatted key and return the bare bones", function() {
				var fullKey = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKl3fSWf4uWm
AYMLOwg/XGT9IgEXHx5GdOeyNxQg8e0wStadP5QFbR9sRM6jPMuIgPM9+yQ7
H1CjrJjQ6iLfocKXqVfEbYWAqcaNZUBagRDqThTwzt//bEw5L6xeVy9cwH0F
Ij52fLL4QQ8C5aia5Kdl+QoQxsnDfYY0akZsr8QHeA7wTQ==
-----END PRIVATE KEY-----";

				var base64Key = _svc.getBase64EncodedPrivateKey( fullKey );

				expect( base64Key ).toBe( "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDKl3fSWf4uWmAYMLOwg/XGT9IgEXHx5GdOeyNxQg8e0wStadP5QFbR9sRM6jPMuIgPM9+yQ7H1CjrJjQ6iLfocKXqVfEbYWAqcaNZUBagRDqThTwzt//bEw5L6xeVy9cwH0FIj52fLL4QQ8C5aia5Kdl+QoQxsnDfYY0akZsr8QHeA7wTQ==" );
			} );
		});
	}
}