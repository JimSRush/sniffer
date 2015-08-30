# sniffer.c

A IPV4 & IPV6 packet sniffer, written in C. Uses the PCAP library and half a dozen netinet header files.

Identifies: 
 <li> IPv4 & IPv6 headers 
  IPv6 extension headers
  Source and destination addresses
  Source and destination ports
  Transport Layer protocols (TCP/UDP/ICMP)</li>
  
  Todo: 
    Check logic for TCP port identification.
    Check logic/refactor to allow for variable size IP header (not always the size of the struct)
  
To compile: gcc -o sniffer sniffer.c -l pcap 
To run: tcpdump -s0 -w - | ./sniffer -
Or: ./sniffer <some file captured from tcpdump or wireshark>
