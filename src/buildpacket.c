#include <libnet.h>
#include <stdlib.h>
#include "buildpacket.h"

void build_packet( char type, char * dst_ip_str )
{
	u_char *cp;
	libnet_t *l; //libnet context
	libnet_ptag_t tcp_tag, ip_tag;
	char *payload;
	u_short payload_s;
	u_long src_ip, dst_ip;
	u_short src_prt, dst_prt;
	char errbuf[LIBNET_ERRBUF_SIZE];

	u_char mac_addr[6];
	int bytes_written;

	int i;           //used for loop of sending packet
	u_short start_port = 77;
	u_short end_port = 100;

	u_int FLAG;     //syn or fin

	if( type == 's')
		FLAG = TH_SYN;
	else
		FLAG = TH_FIN;


	/* Initialize the library. Root privileges are required */
	l = libnet_init( LIBNET_RAW4, 		/* injection type */
			NULL, 			/* network interface */
			errbuf); 		/* error buffer */

	if( l == NULL ){
		fprintf( stderr, "libnet_init( ) failed: %s\n", errbuf );
		exit( EXIT_FAILURE );
	}

	payload = NULL;
	payload_s = 0;
	tcp_tag = ip_tag = LIBNET_PTAG_INITIALIZER;

	/* Getting destination IP address */
	dst_ip = libnet_name2addr4( l, dst_ip_str, LIBNET_DONT_RESOLVE );
	if( dst_ip == -1 ){
		fprintf( stderr, "Error converting destination IP address.\n" );
		libnet_destroy(l);
		exit( EXIT_FAILURE );
	}

	/* Getting own IP address */
	src_ip = libnet_get_ipaddr4( l );
	if( src_ip == -1 ){
		fprintf( stderr, "Error converting source IP address.\n" );
		libnet_destroy( l );
		exit( EXIT_FAILURE );
	}

	/* Building TCP option */
	tcp_tag = libnet_build_tcp_options(
		"\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
		20,
		l,
		0);
     if (tcp_tag == -1)
     {
         fprintf(stderr, "Can't build TCP options: %s\n", libnet_geterror(l));
		 libnet_destroy( l );
         exit( EXIT_FAILURE );
     }

	 /* Building TCP header */
	 tcp_tag = libnet_build_tcp(
		 src_prt,                                    /* source port */
		 dst_prt,                                    /* destination port */
		 0x01010101,                                 /* sequence number */
		 0x02020202,                                 /* acknowledgement num */
		 FLAG,                                       /* control flags */
		 32767,                                      /* window size */
		 0,                                          /* checksum */
		 10,                                         /* urgent pointer */
		 LIBNET_TCP_H + 20 + payload_s,              /* TCP packet size */
		 payload,                                    /* payload */
		 payload_s,                                  /* payload size */
		 l,                                          /* libnet handle */
		 0);                                         /* libnet id */
	 if (tcp_tag == -1) {
		 fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
		 libnet_destroy( l );
		 exit( EXIT_FAILURE );
	 }

	 /* Building IP header */
	 ip_tag = libnet_autobuild_ipv4( LIBNET_IPV4_H + LIBNET_TCP_H +
			 sizeof( payload ), IPPROTO_TCP, dst_ip, l);
	 if( ip_tag == -1 ){
		 fprintf( stderr, "Error building IP header: %s\n", libnet_geterror(l) );
		 libnet_destroy(l);
		 exit( EXIT_FAILURE );
	 }


	 /* Writing packet */

	 for(i = start_port; i <= end_port; ++i ){

		 dst_prt = i;

		 /* Modify TCP header */
		 tcp_tag = libnet_build_tcp(
			 src_prt,                                    /* source port */
			 dst_prt,                                    /* destination port */
			 0x01010101,                                 /* sequence number */
			 0x02020202,                                 /* acknowledgement num */
			 FLAG,                                       /* control flags */
			 32767,                                      /* window size */
			 0,                                          /* checksum */
			 10,                                         /* urgent pointer */
			 LIBNET_TCP_H + 20 + payload_s,              /* TCP packet size */
			 payload,                                    /* payload */
			 payload_s,                                  /* payload size */
			 l,                                          /* libnet handle */
			 tcp_tag);                                   /* libnet id */
			                                             /* !!At fist time,the value is 0 */
		 if (tcp_tag == -1) {
			 fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
			 libnet_destroy( l );
			 exit( EXIT_FAILURE );
		 }


		 bytes_written = libnet_write(l);
		 if ( bytes_written == -1 )
			 fprintf(stderr, "Error writing packet: %s\n",
					 libnet_geterror(l));

		 printf( "----> %s(%d)\n", dst_ip_str,dst_prt );


		 /* Waiting 1 second between each packet */
		 	 sleep(1);
	 }

	 libnet_destroy(l);
	 return ;
}
