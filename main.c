#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

/* output usage */
void display_usage( char *file )
{
	fprintf( stderr, "Usage: %s [option] [target] \n", file );
}

void main( int argc, char ** argv )
{
	int opt;
	char * arg;
	while( ( opt = getopt(argc, argv, "s:d:") ) != -1 ){
		switch( opt ){
		case 's':
			printf( "option s: %s\n", optarg );
			break;
		case 'd':
			printf( "option d: %s\n", optarg );
			break;
		default:
			display_usage( argv[0] );
			exit( -1 );
		}
	}
	
}
