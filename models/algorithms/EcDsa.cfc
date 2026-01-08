/**
 * ECDSA algorithm is a cryptographic algorithm that uses elliptic curve cryptography to sign and verify messages.
 * It is a variant of the DSA algorithm and is considered more secure than the DSA, RSA and HMAC algorithms because
 * it uses a larger key size.
 *
 * This component uses most of the same helpers as the RSA algorithm, but with a different key factory. It also
 * has to do quite a bit of extra work to convert the signature to and from a der sequence byte array.
 */
component extends="Rsa" {

	function init(){
		variables.keyFactory = CreateObject( "java", "java.security.KeyFactory" ).getInstance( "EC" );
	}

// PUBLIC METHODS
	function generateKeys( required string algorithm ) {
		var keyPairGenerator           = CreateObject("java", "java.security.KeyPairGenerator").getInstance( "EC" );
		var ecGenParameterSpecMappings = {
			  SHA256withECDSA = "secp256r1"
			, SHA384withECDSA = "secp384r1"
			, SHA512withECDSA = "secp521r1"
		};
		var spec = CreateObject("java", "java.security.spec.ECGenParameterSpec").init( ecGenParameterSpecMappings[ arguments.algorithm ] );

		keyPairGenerator.initialize( spec );

		var keyPair = keyPairGenerator.generateKeyPair();

		return {
			  privateKey = super._toPem( keyPair.getPrivate().getEncoded(), "PRIVATE KEY" )
			, publicKey  = super._toPem( keyPair.getPublic().getEncoded(), "PUBLIC KEY" )
		};
	}

	function validateSigningKey( required string key, required string algorithm ) {
		try {
			var keyLen = ArrayLen( ToBinary( arguments.key ) );
		} catch( any e ) {
			return false;
		}

		var lenMap   = {
			  SHA256withECDSA = 67
			, SHA384withECDSA = 80
			, SHA512withECDSA = 98
		};
		var validLen = lenMap[ arguments.algorithm ] == keyLen;

		return validLen && super.validateSigningKey( arguments.key );
	}

	function validateVerifyingKey( required string key, required string algorithm ) {
		try {
			var keyLen = ArrayLen( ToBinary( arguments.key ) );
		} catch( any e ) {
			return false;
		}

		var lenMap = {
			  SHA256withECDSA = 91
			, SHA384withECDSA = 120
			, SHA512withECDSA = 158
		};
		var validLen = lenMap[ arguments.algorithm ] == keyLen;

		return validLen && super.validateVerifyingKey( arguments.key );
	}

// PRIVATE HELPERS
	private string function _formatSignature( bytes ){
		var idx = 1;

		// Expect SEQUENCE (0x30)
		if ( bytes[ idx ] != JavaCast("byte", 48)) {
			throw(message="Expected DER SEQUENCE at start of signature");
		}
		idx++;

		// Read SEQUENCE length
		var seqLen = bytes[ idx ];
		idx++;
		if ( BitAnd( seqLen, 128 ) != 0) {
			// Multi-byte length
			var numBytes = BitAnd( seqLen, 127 );
			seqLen = 0;
			for (var i = 1; i <= numBytes; i++) {
				seqLen = BitOr(BitShLn(seqLen, 8), BitAnd(bytes[idx], 255));
				idx++;
			}
		}

		// Decode r
		var rResult = _decodeDerInteger( bytes, idx );
		var rBytes  = rResult.valueBytes;

		idx = rResult.nextIdx;

		// Decode s
		var sResult = _decodeDerInteger(bytes, idx);
		var sBytes  = sResult.valueBytes;


		// Remove leading zeroes (DER may have prepended a 0x00 for positive sign)
		while ( ArrayLen( rBytes ) > 1 && rBytes[ 1 ] == JavaCast( "byte", 0 ) ) {
			ArrayDeleteAt( rBytes, 1 );
		}
		while ( ArrayLen( sBytes ) > 1 && sBytes[1] == JavaCast( "byte", 0 ) ) {
			ArrayDeleteAt( sBytes, 1 );
		}

		// Pad r and s to the same length (max of r/s length, usually curve size in bytes)
		var coordLen = Max( ArrayLen( rBytes ), ArrayLen( sBytes ) );
		while ( ArrayLen( rBytes ) < coordLen ) {
			ArrayPrepend( rBytes, JavaCast( "byte", 0 ) );
		}
		while ( ArrayLen( sBytes ) < coordLen) {
			ArrayPrepend( sBytes, JavaCast( "byte", 0 ) );
		}

		// Concatenate r and s, and return using basic base64url encoding
		// from super class
		var rawSignature = [];
		ArrayAppend( rawSignature, rBytes, true );
		ArrayAppend( rawSignature, sBytes, true );
		rawSignature = JavaCast( "byte[]", rawSignature );

		return super._formatSignature( rawSignature );
	}

	private function _decodeDerInteger( bytes, startIdx ) {
		var idx = arguments.startIdx;

		if (arguments.bytes[idx] != JavaCast("byte", 2)) {
			throw(message="Expected INTEGER tag at position " & idx);
		}
		idx++;
		var length = arguments.bytes[idx];
		idx++;
		if ( BitAnd( length, 128 ) != 0 ) {
			// Multi-byte length
			var numBytes = BitAnd( length, 127 );
			length = 0;
			for (var i = 1; i <= numBytes; i++) {
				length = BitOr( BitShLn( length, 8 ), BitAnd( arguments.bytes[idx], 255 ) );
				idx++;
			}
		}
		var valueBytes = [];
		for (var i = 1; i <= length; i++) {
			ArrayAppend(valueBytes, arguments.bytes[idx]);
			idx++;
		}
		return { valueBytes = valueBytes, nextIdx = idx };
	}

	private function _convertSignatureToByteArray( signature ){
		/*
			A raw signature string needs converting to a der sequence byte array.
			which is a little nuanced. The end result is along the lines of:

				[ SEQ, SIZEALL, INT, SIZER, [R], INT, SIZES, [S] ]

			Where

			* SEQ is a hardcoded byte value of 48
			* SIZEALL is the length of the signature + the other parts
			* INT is a hardcoded byte value of 2
			* SIZER is the length of the r coordinate
			* [R] is the r coordinate
			* SIZES is the length of the s coordinate
			* [S] is the s coordinate

			The r and s coordinates are the raw signature split into two parts.
			Each coordinate is then stripped of leading zeros and then padded with
			a leading zero in some cases.

			Sizes gt than 127 will take up multiple array slots in the byte array and
			the sizing needs to take this into account.

			FUN.
		*/

		var sigBytes = CreateObject( "java", "java.util.Base64" ).getUrlDecoder().decode( arguments.signature );
		var sigLen   = ArrayLen( sigBytes );
		var coordLen = sigLen / 2;
		var rBytes   = _trimAndPadZeroesForDerSequence( ArraySlice( sigBytes, 1, coordLen ) );
		var sBytes   = _trimAndPadZeroesForDerSequence( ArraySlice( sigBytes, coordLen + 1, coordLen ) );

		var rDer           = _createDerPartArray( rBytes );
		var sDer           = _createDerPartArray( sBytes );
		var derSeq         = [ JavaCast( "byte", 48 ) ];
		var seqLengthBytes = _encodeDerLength( ArrayLen( rDer ) + ArrayLen( sDer ) );

		ArrayAppend( derSeq, seqLengthBytes, true );
		ArrayAppend( derSeq, rDer, true );
		ArrayAppend( derSeq, sDer, true );

		return JavaCast( "byte[]", derSeq );
	}

	private function _createDerPartArray( required array bytes ){
		var derPartArr = [ JavaCast( "byte", 2 ) ];
		var lengthBytes = _encodeDerLength( ArrayLen( arguments.bytes ) );

		ArrayAppend( derPartArr, lengthBytes, true );
		ArrayAppend( derPartArr, arguments.bytes, true );

		return derPartArr;
	}

	private function _encodeDerLength( required numeric length ){
		var lengthBytes = [];

		if ( arguments.length <= 127 ) {
			ArrayAppend( lengthBytes, JavaCast( "byte", arguments.length ) );
		} else {
			var lengthValue = arguments.length;
			var tempBytes = [];

			while ( lengthValue > 0 ) {
				ArrayPrepend( tempBytes, JavaCast( "byte", BitAnd( lengthValue, 255 ) ) );
				lengthValue = BitShRn( lengthValue, 8 );
			}

			ArrayAppend( lengthBytes, JavaCast( "byte", 128 + ArrayLen( tempBytes ) ) );
			ArrayAppend( lengthBytes, tempBytes, true );
		}

		return lengthBytes;
	}

	private function _trimAndPadZeroesForDerSequence( required array bytes ){
		var processed = arguments.bytes;
		var i         = 1;

		while ( i <= ArrayLen( processed ) && processed[ i ] == 0 ) {
			i++;
		}
		if ( i > 1 ) {
			processed = ArraySlice( processed, i, ArrayLen( processed ) - i + 1 );
		}

		if ( ArrayLen( processed ) == 0 ) {
			processed = [ JavaCast( "byte", 0 ) ];
		} else if ( BitAnd( processed[ 1 ], 128 ) ) {
			ArrayPrepend( processed, JavaCast( "byte", 0 ) );
		}

		return processed;
	}



}