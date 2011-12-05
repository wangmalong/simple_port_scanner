#include "captpacket.h"

const u_char printable( const u_char  c )
{
	if(c > 31 && c < 128)
		return c;
	else
		return '.';
}

void print_payload( const u_char * payload, int len )
{
   	int line_width = 16;
	int count = len / line_width;
	int i = 0;
	int index = 0;
	char str[17] = {'\0'};

	printf( "\n\n\n" );

	while( count-- ){
		for( i = 0; i < line_width; i++, index++ ){
			printf( "%02X ", payload[index] );
			str[i] = printable( payload[index] );
		}
		str[i] = '\0';
		printf( "\t%s\n", str );
	}
	for( i = 0; i < line_width; i++, index++ ){
		if( index < len ){
			printf( "%02X ", payload[index] );
			str[i] = printable( payload[index] );
		}
		else
			printf( "   " );
		str[i+1] = '\0';

	}
	printf( "\t%s\n", str );

	printf( "\n\n\n" );
}




void tcp_protocol_packet_callback(
	u_char *argument, const struct pcap_pkthdr* packet_header,
	const u_char * packet_content )
{
	/* IP part */
	struct sniff_ip *ip_protocol;
	u_int ip_header_length;
	u_int offset;
	u_char tos;    //service quality
	u_int16_t checksum;
	/* get IP protocol payload, skip the ethernet header*/
	ip_protocol = ( struct sniff_ip * )( packet_content + 14 );
	checksum = ntohs( ip_protocol->ip_sum ); //get the checksum
	ip_header_length = ip_protocol->ip_vhl >> 2;     //get header length
	tos = ip_protocol->ip_tos;               //get service quality
	offset = ntohs( ip_protocol->ip_off );   //fragment offset


	/* TCP part */
	struct sniff_tcp *tcp_protocol;
	struct servent *service;
	u_char flags;
	int tcp_header_length;
	u_short source_port;
	u_short destination_port;
	u_short windows;
	u_short urgent_pointer;
	u_int sequence;
	u_int acknowledgement;

	/* analysis the ip content  */
/*	printf( "\n---------- IP Protocol ( Network Layer ) ----------\n" );
	printf( "IP Version : %d\n", ip_protocol->ip_vhl/16 );
	printf( "src addr :%s\n", inet_ntoa(ip_protocol->ip_src) );
	printf( "dst addr :%s\n", inet_ntoa(ip_protocol->ip_dst) );
	printf( "Header length : %d\n", ip_header_length );
	printf( "TOS : %d\n", tos );
	printf( "Total length : %d\n", ntohs( ip_protocol->ip_len ) );
	printf( "Identification : %d\n", ntohs( ip_protocol->ip_id ) );
	printf( "Offset : %d\n", ( offset & 0x1fff ) * 8 );
	printf( "TTL : %d\n", ip_protocol->ip_ttl );  //time to live of IP
	printf( "Protocol : %d\n", ip_protocol->ip_p );
*/

	/*get tcp protocol content, skip ethernet and IP header*/
	tcp_protocol = ( struct sniff_tcp * )( packet_content+14+20 );
	source_port = ntohs( tcp_protocol->th_sport );
	destination_port = ntohs( tcp_protocol->th_dport );
	tcp_header_length = tcp_protocol->th_offx2 * 4;
	sequence = ntohl( tcp_protocol->th_ack );
	windows = ntohs( tcp_protocol->th_win );
	urgent_pointer = ntohs( tcp_protocol->th_urp );

	flags = tcp_protocol->th_flags;
	checksum = ntohs( tcp_protocol->th_sum );

	printf( "\n---------- TCP Protocol ( Transport Layer ) ----------\n" );

	printf( "%s", inet_ntoa(ip_protocol->ip_src) );
	printf("---->");
	printf( "%s\n", inet_ntoa(ip_protocol->ip_dst) );
	printf( "Sorc Port : %d \n", source_port );
	printf( "Dest Port : %d \n", destination_port );

	service = getservbyport( htons(destination_port), NULL);
	if(service != NULL ){
		printf("the service is %s \n", service->s_name);
		printf("the port is %d\n", ntohs(service->s_port));
		printf("the protocol is %s \n", service->s_proto);
	}

/*	switch( destination_port ){
	case 80 : printf( "HTTP protocol\n" ); break;
	case 21 : printf( "FTP protocol\n" ); break;
	case 23 : printf( "TELNET protocol\n" ); break;
	case 25 : printf( "SMTP protocol\n" ); break;
	case 110 : printf( "POP3 protocol\n" ); break;
	default : break;
	}

	printf( "Sequence Number: %u\n", sequence );
	printf( "Acknowledgement Number : %u\n", acknowledgement );
	printf( "Header Length : %d\n", tcp_header_length );
	printf( "Reserved : %d\n", tcp_protocol->th_offx2 );

	printf( "Flags : " );
	if( flags & 0x08 ) printf( "PSH " );
	if( flags & 0x10 ) printf( "ACK " );
	if( flags & 0x02 ) printf( "SYN " );
	if( flags & 0x20 ) printf( "URG " );
	if( flags & 0x01 ) printf( "FIN " );
	if( flags & 0x04 ) printf( "RST " );
	printf( "\n" );

	printf( "Window Size : %d\n", windows );
	printf( "Checksum : %d\n", checksum );
	printf( "Urgent pointer : %d\n", urgent_pointer );
	print_payload( packet_content, packet_header->len);
*/
}

void capture_package( char * dst_ip_str )
{
	pcap_t* pcap_handle;
	char error_content[PCAP_ERRBUF_SIZE];
	char *net_interface;
	struct bpf_program bpf_filter;
	/* "" indicates capture all packet*/
	char bpf_filter_string[] = "tcp";
	bpf_u_int32 net_mask;
	bpf_u_int32 net_ip;

	/* get network interface */
	net_interface = pcap_lookupdev( error_content );
	if(net_interface == NULL){
		fprintf(stderr, "Couldn't find default device: %s\n",
           error_content);
		exit(1);
	}
	printf("Device: %s\n", net_interface);

	/* get network addr, mask */
	if( pcap_lookupnet( net_interface, &net_ip,
                     &net_mask, error_content ) == -1){
		fprintf(stderr, "Couldn't get netmask for device %s\n",
            net_interface);
		exit(1);
	}

	/* open network interface */
	pcap_handle = pcap_open_live( net_interface, BUFSIZ,
                               1, 0, error_content );
	if(pcap_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n",
           net_interface, error_content);
		exit(1);
	}

	//sprintf(bpf_filter_string, "src %s and dst %s tcp", net_ip, dst_ip_str);
	/* compile the filter */
	if( pcap_compile( pcap_handle, &bpf_filter,
                   bpf_filter_string, 0, net_ip ) == -1){
		fprintf(stderr, "couldn't parse filter: %s: %s\n",
           bpf_filter_string, pcap_geterr(pcap_handle));
		exit(1);
	}
	/* set the filter */
	if( pcap_setfilter( pcap_handle, &bpf_filter ) == -1 ){
		fprintf(stderr, "couldn't install filter: %s: %s\n",
          bpf_filter_string, pcap_geterr(pcap_handle));
		exit(1);
	}

	//if( pcap_datalink( pcap_handle ) != DLT_EN10MB ) //return link layer type
	//	return;
	/* register the call back function, capture the packet in loop
	   then, callback function analysis the packet */
	pcap_loop( pcap_handle, -1, tcp_protocol_packet_callback, NULL );
	pcap_close( pcap_handle );

}
