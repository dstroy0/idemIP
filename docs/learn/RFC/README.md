# The law

The RFC text every rule in `src/` is written against, as published by the RFC Editor. A comment
that cites a section is quoting one of these files, and an audit that reports a finding read it
here.

Read the section, do not recall it:

```
grep -n "MUST-66" docs/learn/RFC/rfc9293.txt
sed -n '3500,3530p' docs/learn/RFC/rfc9293.txt
```

100 documents.

| RFC | Title |
| --- | --- |
| [768](rfc768.txt) | User Datagram Protocol |
| [791](rfc791.txt) | Internet Protocol |
| [792](rfc792.txt) | Internet Control Message Protocol |
| [815](rfc815.txt) | IP Datagram Reassembly Algorithms |
| [826](rfc826.txt) | An Ethernet Address Resolution Protocol -- or -- Converting Network Protocol Addresses to 48.bit Ethernet Address for Transmission on Ethernet Hardware |
| [894](rfc894.txt) | A Standard for the Transmission of IP Datagrams over Ethernet Networks |
| [907](rfc907.txt) | Host Access Protocol Specification |
| [919](rfc919.txt) | BROADCASTING INTERNET DATAGRAMS |
| [950](rfc950.txt) | Internet Standard Subnetting Procedure |
| [1035](rfc1035.txt) | Domain Names - Implementation and Specification |
| [1042](rfc1042.txt) | A Standard for the Transmission of IP Datagrams over IEEE 802 Networks |
| [1044](rfc1044.txt) | Internet Protocol on Network Systems HYPERchannel Protocol Specification |
| [1055](rfc1055.txt) | A Nonstandard for Transmission of IP Datagrams over Serial Lines: SLIP |
| [1071](rfc1071.txt) | Computing the Internet Checksum |
| [1112](rfc1112.txt) | Host Extensions for IP Multicasting |
| [1122](rfc1122.txt) | Requirements for Internet Hosts -- Communication Layers |
| [1123](rfc1123.txt) | Requirements for Internet Hosts -- Application and Support |
| [1144](rfc1144.txt) | Compressing TCP/IP Headers for Low-Speed Serial Links |
| [1155](rfc1155.txt) | Structure and Identification of Management Information for TCP/IP-based Internets |
| [1188](rfc1188.txt) | A Proposed Standard for the Transmission of IP Datagrams over FDDI Networks |
| [1191](rfc1191.txt) | Path MTU Discovery |
| [1213](rfc1213.txt) | Management Information Base for Network Management of TCP/IP-based internets: MIB-II |
| [1337](rfc1337.txt) | TIME-WAIT Assassination Hazards in TCP |
| [1533](rfc1533.txt) | DHCP Options and BOOTP Vendor Extensions |
| [1542](rfc1542.txt) | Clarifications and Extensions for the Bootstrap Protocol |
| [1812](rfc1812.txt) | Requirements for IP Version 4 Routers |
| [1858](rfc1858.txt) | Security Considerations for IP Fragment Filtering |
| [2011](rfc2011.txt) | SNMPv2 Management Information Base for the Internet Protocol using SMIv2 |
| [2018](rfc2018.txt) | TCP Selective Acknowledgment Options |
| [2113](rfc2113.txt) | IP Router Alert Option |
| [2119](rfc2119.txt) | Key words for use in RFCs to Indicate Requirement Levels |
| [2131](rfc2131.txt) | Dynamic Host Configuration Protocol |
| [2132](rfc2132.txt) | DHCP Options and BOOTP Vendor Extensions |
| [2181](rfc2181.txt) | Clarifications to the DNS Specification |
| [2236](rfc2236.txt) | Internet Group Management Protocol, Version 2 |
| [2464](rfc2464.txt) | Transmission of IPv6 Packets over Ethernet Networks |
| [2465](rfc2465.txt) | Management Information Base for IP Version 6: Textual Conventions and General Group |
| [2466](rfc2466.txt) | Management Information Base for IP Version 6: ICMPv6 Group |
| [2578](rfc2578.txt) | Structure of Management Information Version 2 (SMIv2) |
| [2579](rfc2579.txt) | Textual Conventions for SMIv2 |
| [2710](rfc2710.txt) | Multicast Listener Discovery (MLD) for IPv6 |
| [2827](rfc2827.txt) | Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing |
| [3021](rfc3021.txt) | Using 31-Bit Prefixes on IPv4 Point-to-Point Links |
| [3128](rfc3128.txt) | Protection Against a Variant of the Tiny Fragment Attack |
| [3306](rfc3306.txt) | Unicast-Prefix-based IPv6 Multicast Addresses |
| [3376](rfc3376.txt) | Internet Group Management Protocol, Version 3 |
| [3465](rfc3465.txt) | TCP Congestion Control with Appropriate Byte Counting (ABC) |
| [3542](rfc3542.txt) | Advanced Sockets Application Program Interface (API) for IPv6 |
| [3596](rfc3596.txt) | DNS Extensions to Support IP Version 6 |
| [3646](rfc3646.txt) | DNS Configuration options for Dynamic Host Configuration Protocol for IPv6 (DHCPv6) |
| [3810](rfc3810.txt) | Multicast Listener Discovery Version 2 (MLDv2) for IPv6 |
| [3828](rfc3828.txt) | The Lightweight User Datagram Protocol (UDP-Lite) |
| [3927](rfc3927.txt) | Dynamic Configuration of IPv4 Link-Local Addresses |
| [3956](rfc3956.txt) | Embedding the Rendezvous Point (RP) Address in an IPv6 Multicast Address |
| [4007](rfc4007.txt) | IPv6 Scoped Address Architecture |
| [4086](rfc4086.txt) | Randomness Requirements for Security |
| [4193](rfc4193.txt) | Unique Local IPv6 Unicast Addresses |
| [4291](rfc4291.txt) | IP Version 6 Addressing Architecture |
| [4302](rfc4302.txt) | IP Authentication Header |
| [4303](rfc4303.txt) | IP Encapsulating Security Payload (ESP) |
| [4343](rfc4343.txt) | Domain Name System (DNS) Case Insensitivity Clarification |
| [4443](rfc4443.txt) | Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification |
| [4632](rfc4632.txt) | Classless Inter-domain Routing (CIDR): The Internet Address Assignment and Aggregation Plan |
| [4861](rfc4861.txt) | Neighbor Discovery for IP version 6 (IPv6) |
| [4862](rfc4862.txt) | IPv6 Stateless Address Autoconfiguration |
| [4884](rfc4884.txt) | Extended ICMP to Support Multi-Part Messages |
| [4941](rfc4941.txt) | Privacy Extensions for Stateless Address Autoconfiguration in IPv6 |
| [5227](rfc5227.txt) | IPv4 Address Conflict Detection |
| [5342](rfc5342.txt) | IANA Considerations and IETF Protocol Usage for IEEE 802 Parameters |
| [5452](rfc5452.txt) | Measures for Making DNS More Resilient against Forged Answers |
| [5681](rfc5681.txt) | TCP Congestion Control |
| [5722](rfc5722.txt) | Handling of Overlapping IPv6 Fragments |
| [5942](rfc5942.txt) | IPv6 Subnet Model: The Relationship between Links and Subnet Prefixes |
| [5952](rfc5952.txt) | A Recommendation for IPv6 Address Text Representation |
| [5961](rfc5961.txt) | Improving TCP's Robustness to Blind In-Window Attacks |
| [6056](rfc6056.txt) | Recommendations for Transport-Protocol Port Randomization |
| [6106](rfc6106.txt) | IPv6 Router Advertisement Options for DNS Configuration |
| [6274](rfc6274.txt) | Security Assessment of the Internet Protocol Version 4 |
| [6275](rfc6275.txt) | Mobility Support in IPv6 |
| [6298](rfc6298.txt) | Computing TCP's Retransmission Timer |
| [6325](rfc6325.txt) | Routing Bridges (RBridges): Base Protocol Specification |
| [6335](rfc6335.txt) | Internet Assigned Numbers Authority (IANA) Procedures for the Management of the Service Name and Transport Protocol Port Number Registry |
| [6528](rfc6528.txt) | Defending against Sequence Number Attacks |
| [6724](rfc6724.txt) | Default Address Selection for Internet Protocol Version 6 (IPv6) |
| [6890](rfc6890.txt) | Special-Purpose IP Address Registries |
| [6980](rfc6980.txt) | Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery |
| [7042](rfc7042.txt) | IANA Considerations and IETF Protocol and Documentation Usage for IEEE 802 Parameters |
| [7112](rfc7112.txt) | Implications of Oversized IPv6 Header Chains |
| [7323](rfc7323.txt) | TCP Extensions for High Performance |
| [7527](rfc7527.txt) | Enhanced Duplicate Address Detection |
| [8106](rfc8106.txt) | IPv6 Router Advertisement Options for DNS Configuration |
| [8174](rfc8174.txt) | Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words |
| [8200](rfc8200.txt) | Internet Protocol, Version 6 (IPv6) Specification |
| [8201](rfc8201.txt) | Path MTU Discovery for IP version 6 |
| [8415](rfc8415.txt) | Dynamic Host Configuration Protocol for IPv6 (DHCPv6) |
| [8504](rfc8504.txt) | IPv6 Node Requirements |
| [8900](rfc8900.txt) | IP Fragmentation Considered Fragile |
| [8981](rfc8981.txt) | Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6 |
| [9260](rfc9260.txt) | Stream Control Transmission Protocol |
| [9293](rfc9293.txt) | Transmission Control Protocol (TCP) |
