Build & Run Server Script:
gcc server.c -o server -lpcap
./server

Build & Run Client Script:
gcc client.c -o client -lpcap
./client

Note: Client source ip address statically declared 192.168.1.1
for debugging

Note: Server only reply icmp requests from 192.168.1.1. it also
statically declared at server code.

Note: network interface must declared statically on MacOS,
because pcap_lookupdev returns wrong interface