# ZETASniffer

## Usage

`./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}`

## Documentation
The networking part was programmed using the LIBCAP library[^3]. 

Fitlers are built in the `Sniffer` constructor by buildilng a **BPF** filter expressions[^2], which are then passed to the `pcap_compile()` function.

Other sources of information were pcap tutorials[^1][^4].

### Class diagram

## External libraries

- **args**[^5] - A single-header C++ library used to parse command line arguments. The library is the `args.hxx` file. Source: [Github repository](https://github.com/Taywee/args).

## Tests
All testing was done comparing the output of Wireshark with my sniffer. Below are some examples of comparison between Wireshark and my implementation.
Packets were simulated using the NetCat tool (`nc`).


<!--- Resources --->
[^1]: *Hargrave, V. (2012, December 9). Develop a Packet Sniffer with Libpcap.* vichargrave.github.io. https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap
[^2]: *BPF Packet Filtering Expressions — nProbe 10.1 documentation.* (n.d.). https://www.ntop.org/guides/nprobe/bpf_expressions.html
[^3]: *Programming with pcap | TCPDUMP & LIBPCAP.* (n.d.). https://www.tcpdump.org/pcap.html
[^4]: *libpcap packet capture tutorial.* (n.d.). http://yuba.stanford.edu/~casado/pcap/section3.html
[^5]: *args*. A simple header-only C++ argument parser library. https://github.com/Taywee/args/tree/master
