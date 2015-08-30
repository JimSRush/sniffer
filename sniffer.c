/* sniffer.c
 *
 * main() and gotPacket() by David C Harrison (david.harrison@ecs.vuw.ac.nz) July 2015, used here with attribution.
 *
 * Heavily extended and modified from the original. All other work is from Jim Rush unless otherwise specified.
 * 
 * Use as-is, modification, and/or inclusion in derivative works is permitted only if 
 * the original author (David) is credited. 
 * 
 * **Usage*
 * To compile: gcc -o sniffer sniffer.c -l pcap 
 * To run: tcpdump -s0 -w - | ./sniffer -
 * Or: ./sniffer <some file captured from tcpdump or wireshark>
 */


#include <stdio.h>
#include <ctype.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>//need this for icmp for ipv4
#include <arpa/inet.h>//need this for inet_ntoa

static int packetCount = 0;	



void check_ICMP_6_type(uint8_t type){
	printf("ICMP6 type: %u\n", type);// need to fix the cast
	//printf("Hey");//do comparisons here

}

//Ouch. This is what we do when we have an IPV4 ICMP packet
void check_ICMP_4_type(u_int8_t type) {

	printf("ICMP4 type: ");
	switch(type) {
		case ICMP_ECHOREPLY :
			printf("Echo reply\n");
			break;
		case ICMP_SOURCE_QUENCH :
			printf ("Source Quench\n");
			break;
		case ICMP_REDIRECT :
			printf("Redirect\n");
			break;
		case ICMP_ECHO :
			printf("Echo\n");
			break;
		case ICMP_TIME_EXCEEDED :
			printf("Time Exceeded\n");
			break;
		case ICMP_PARAMETERPROB :
			printf ("Parameter problem\n");
			break;
		case ICMP_TIMESTAMP :
			printf("Timestamp request\n");
			break;
		case ICMP_TIMESTAMPREPLY :
			printf ("Timestamp reply\n");
			break;
		case ICMP_INFO_REQUEST :
			printf("Info request\n");
			break;
		case ICMP_INFO_REPLY :
			printf("Informatino reply\n");
			break;
		case ICMP_ADDRESS :
			printf ("Address mask request\n");
			break;
		case ICMP_ADDRESSREPLY :
			printf("Address mask reply\n");
			break;
		default: 
			printf("Other\n");
	}
}


//passed a TCP packet
void got_TCP(const u_char *packet){
	struct tcphdr *tcph = (struct tcphdr*) (packet);
	printf("Protocol: TCP\n");
	printf("Source port: %u\n", tcph->source);
	printf("Destination port: %u\n", tcph -> dest);
	
	
}

//passed a UDP packet
void got_UDP(const u_char *packet) {
	struct udphdr *udp_header = (struct udphdr*)(packet);
	printf("Protocol: UDP\n");
	printf("Source port: %u\n", udp_header->source);
	printf("Destination port: %u\n", udp_header->dest);
}

//passed a ICMP_ipv4 packet
void got_ICMP_ipv4(const u_char *packet){
	printf("Protocol: ICMP_ipv4\n");
	struct icmphdr *icmp_header = (struct icmphdr*) (packet);//cast to ICMP header
	check_ICMP_4_type(icmp_header->type);//check to see what's in the headr
}

void got_ICMP_ipv6(const u_char *packet) {
		
		struct icmp6_hdr *icmp6_header = (struct icmp6_hdr*) (packet);//cast to ICMP 6 header
		printf("Protocol: ICMP_ipv6\n");
		check_ICMP_6_type(icmp6_header->icmp6_type);
	}

void got_ip4_packet(const u_char *packet) {//now points at first byte of IP packet
	struct ip *iph = (struct ip*) (packet); //cast the ipv4 packet into the struct
	printf("Source address: %s\n",  inet_ntoa(iph->ip_src));//convert to ip address
	printf("Destination address: %s\n",  inet_ntoa(iph->ip_dst));//convert to ip address
	printf("Protocol type: ");
	//printf("") //need to print size of the Payload
	switch(iph->ip_p){
		case IPPROTO_TCP :
			got_TCP(packet + sizeof(struct ip));
			//got_TCP
			break;
		case IPPROTO_UDP :
			got_UDP(packet + sizeof(struct ip));
			//got UDP 
			break;
		case IPPROTO_ICMP :
			got_ICMP_ipv4(packet + sizeof(struct ip));
			//got_ICMP_ipv4
			break;
		default : 
			printf("Not sure what carrier protocol this is.\n");
	}	
}


//This is the recursive method to parse the ipv6 extension headers/protocol
void parse_ext_headers(const u_char *packet, uint8_t next_header){
	//printf("Hello\n");
	switch(next_header) {
		case IPPROTO_TCP :
			got_TCP(packet + sizeof(struct ip6_hdr));
			break;
		case IPPROTO_UDP :
			got_UDP(packet + sizeof(struct ip6_hdr));
			break;
		case IPPROTO_ICMPV6 :
			got_ICMP_ipv6(packet + sizeof(struct ip6_hdr));
			break;
		case IPPROTO_HOPOPTS :
			printf("Extension header type: Hop-By-Hop-Options header\n");
			struct ip6_hbh *ip6_hop_by_hop = (struct ip6_hbh*) (packet);//it's a hbh header, so cast to the struct
			parse_ext_headers(packet + ip6_hop_by_hop->ip6h_len, ip6_hop_by_hop->ip6h_nxt); //recurse
			break;
		case IPPROTO_ROUTING :
			printf("Extension header type: IPv6 routing header\n");
			struct ip6_rthdr *ip6_routing_header = (struct ip6_rthdr*) (packet);
			parse_ext_headers(packet + ip6_routing_header->ip6r_len, ip6_routing_header->ip6r_nxt);
 			break;
		case IPPROTO_FRAGMENT :
			printf("Extension header type: IPv6 fragmentation header\n");
			struct ip6_frag *ip6_frag_hdr = (struct ip6_frag*) (packet);
			parse_ext_headers(packet + sizeof (struct ip6_frag), ip6_frag_hdr->ip6f_nxt);
			break;
		case IPPROTO_NONE :
			printf("Extension header type: None\n");
			break;
		case IPPROTO_MH :
			printf("Extension header type: IPv6 mobility header\n");
			//could not find any to test
			break;
		case IPPROTO_DSTOPTS :
			printf("Extension header type: IPv6 destination options\n");
			struct ip6_dest *ip6_dest_hdr = (struct ip6_dest*) (packet);
			parse_ext_headers(packet + ip6_dest_hdr->ip6d_len, ip6_dest_hdr->ip6d_nxt);
			break;
		default :
			printf("Extension header type: Unknown\n");
			break;
	}

}

//Function for dealing with IPV6
void got_ipv6_packet(const u_char *packet){
	struct ip6_hdr *ipv6_header = (struct ip6_hdr*) (packet); //cast the packet to a ip6 header
	
	char source[INET6_ADDRSTRLEN];//declare source address
	char destination[INET6_ADDRSTRLEN];//declare destination address
	
	inet_ntop(AF_INET6, &(ipv6_header->ip6_src), source, INET6_ADDRSTRLEN);//pull out source into source char[]
	inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destination, INET6_ADDRSTRLEN);//dest
	
	printf("Source address: %s\n", source);
	printf("Destination address: %s\n", destination);
	//What protocol do we have?
	//It may not be a protocol, but a chain of extension headers and THEN a protocol
	int next_header = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;//pull out next header and pass to method
	parse_ext_headers(packet + sizeof(struct ip6_hdr), next_header); //send off the packet and the next header to be looked at

}

//Called on every packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	printf("\n");//separate
	struct ether_header *eh = (struct ether_header*) packet;
	//check to see what type it is
	printf("Packet number: %d\n", packetCount);
	packetCount++;
	printf("Ether type: " );
	switch(ntohs(eh->ether_type)) {//convert from host byte order to network byte
		
		case ETHERTYPE_IP :
			printf("IPV4\n");
			got_ip4_packet(packet + sizeof(struct ether_header));
			break;
		case ETHERTYPE_IPV6 :
			printf("IPV6\n");
			got_ipv6_packet(packet  + sizeof(struct ether_header));//should be the same size ethernet header???
			break;
		default :
			printf("Unknown/Other\n");
	}

}


int main (int argc, char **argv){
	//Check for bogus arguments
	if (argc < 2) {
		fprintf(stderr, "Must have an argument, either a file name or '-'\n");
		return -1;
	}

	pcap_t *handle = pcap_open_offline(argv[1], NULL);//Open the packet and assign to a pointer
	pcap_loop(handle, 1024*1024, got_packet, NULL);//passed pointer to function
	pcap_close(handle); //close the pcap session

	return 0;

}