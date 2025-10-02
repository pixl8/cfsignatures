component {
	this.name = "cfSignatures Test Suite";

	this.mappings[ '/tests'        ] = ExpandPath( "/" );
	this.mappings[ '/testbox'      ] = ExpandPath( "/testbox" );
	this.mappings[ '/cfsignatures' ] = ExpandPath( "../" );

	setting requesttimeout=60000;
}
