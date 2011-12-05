#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "portscan.h"

/* output usage */
void display_usage( char *file )
{
	fprintf( stderr, "Usage: %s [option] [target] \n", file );
}

int main( int argc, char ** argv )
{
	int opt;
	char type;
	char * dst_ip_str;

	type = '.';
	while( ( opt = getopt(argc, argv, "s:f:") ) != -1 ){
		switch( opt ){
		case 's':
			printf( "option s: %s\n", optarg );
			type = 's';
			dst_ip_str = optarg;
			break;
		case 'f':
			printf( "option f: %s\n", optarg );
			type = 'f';
			dst_ip_str = optarg;
			break;
		default:
			display_usage( argv[0] );
			exit( -1 );
		}
	}

	if( type == '.' ){
		display_usage( argv[0] );
		exit(-1);
	}

	port_scan( type, dst_ip_str );
	return 0;
}

