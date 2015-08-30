# sniffer.c

A Ethernet packet sniffer, that identifies IPV4 & IPV6 ethertypes. Written in C. 
Uses the PCAP library and half a dozen netinet header files.

<h1>Identifies:</h1>
 <li> IPv4 & IPv6 headers</li>
 <li>IPv6 extension headers</li>
 <li>Source and destination addresses</li>
 <li>Source and destination ports</li>
 <li>Transport Layer protocols (TCP/UDP/ICMP)</li>
  
 <h1>Todo:</h1> 
 <li>Check logic for TCP port identification</li>
 <li>Check logic/refactor to allow for variable size IP header (not always the size of the struct)</li>
  
To compile: gcc -o sniffer sniffer.c -lpcap 
To run: tcpdump -s0 -w - | ./sniffer -
Or: ./sniffer <some file captured from tcpdump or wireshark>
