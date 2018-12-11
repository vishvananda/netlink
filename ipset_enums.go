package netlink

import "fmt"

type ipsetTypeEnum string

func (t ipsetTypeEnum) toString() string {
	return string(t)
}

// possible IPSet types
const (
	IPSetHashIP         ipsetTypeEnum = "hash:ip"
	IPSetBitmapIP       ipsetTypeEnum = "bitmap:ip"
	IPSetBitmapIPMac    ipsetTypeEnum = "bitmap:ip,mac"
	IPSetBitmapPort     ipsetTypeEnum = "bitmap:port"
	IPSetHashMac        ipsetTypeEnum = "hash:mac"
	IPSetHashNet        ipsetTypeEnum = "hash:net"
	IPSetHashNetNet     ipsetTypeEnum = "hash:net,net"
	IPSetHashIPPort     ipsetTypeEnum = "hash:ip,port"
	IPSetHashNetPort    ipsetTypeEnum = "hash:net,port"
	IPSetHashIPPortIP   ipsetTypeEnum = "hash:ip,port,ip"
	IPSetHashIPPortNet  ipsetTypeEnum = "hash:ip,port,net"
	IPSetHashIPMark     ipsetTypeEnum = "hash:ip,mark"
	IPSetHashNetPortNet ipsetTypeEnum = "hash:net,port,net"
	IPSetHashNetIface   ipsetTypeEnum = "hash:net,iface"
	IPSetListSet        ipsetTypeEnum = "list:set"
)

func ipsetTypeEnumFromString(str string) ipsetTypeEnum {
	switch str {
	case "hash:ip":
		return IPSetHashIP
	case "bitmap:ip":
		return IPSetBitmapIP
	case "bitmap:ip,mac":
		return IPSetBitmapIPMac
	case "bitmap:port":
		return IPSetBitmapPort
	case "hash:mac":
		return IPSetHashMac
	case "hash:net":
		return IPSetHashNet
	case "hash:net,net":
		return IPSetHashNetNet
	case "hash:ip,port":
		return IPSetHashIPPort
	case "hash:net,port":
		return IPSetHashNetPort
	case "hash:ip,port,ip":
		return IPSetHashIPPortIP
	case "hash:ip,port,net":
		return IPSetHashIPPortNet
	case "hash:ip,mark":
		return IPSetHashIPMark
	case "hash:net,port,net":
		return IPSetHashNetPortNet
	case "hash:net,iface":
		return IPSetHashNetIface
	case "list:set":
		return IPSetListSet
	default:
		panic(fmt.Errorf("Invalid IPSet type %q", str))
	}
}

type ipsetFamilyEnum uint8

func (f ipsetFamilyEnum) toUint8() uint8 {
	return uint8(f)
}

// http://git.netfilter.org/ipset/tree/include/libipset/nfproto.h
const (
	NFPROTO_IPV4 ipsetFamilyEnum = 2
	NFPROTO_IPV6 ipsetFamilyEnum = 10
)

func ipsetFamilyEnumFromByte(b uint8) ipsetFamilyEnum {
	switch b {
	case 2:
		return NFPROTO_IPV4
	case 10:
		return NFPROTO_IPV6
	default:
		panic(fmt.Errorf("Invalid IPSet family %d", b))
	}
}

type ipsetProtoEnum uint8

// possible IPSet protocols
const (
	IPSetPortRangeAny              ipsetProtoEnum = 0
	IPSetPortRangeICMP             ipsetProtoEnum = 1   // Internet Control Message Protocol     RFC 792
	IPSetPortRangeIGMP             ipsetProtoEnum = 2   // Internet Group Management Protocol     RFC 1112
	IPSetPortRangeGGP              ipsetProtoEnum = 3   // Gateway-to-Gateway Protocol     RFC 823
	IPSetPortRangeIP_in_IP         ipsetProtoEnum = 4   // IP in IP (encapsulation)     RFC 2003
	IPSetPortRangeST               ipsetProtoEnum = 5   // Internet Stream Protocol     RFC 1190, RFC 1819
	IPSetPortRangeTCP              ipsetProtoEnum = 6   // Transmission Control Protocol     RFC 793
	IPSetPortRangeCBT              ipsetProtoEnum = 7   // Core-based trees     RFC 2189
	IPSetPortRangeEGP              ipsetProtoEnum = 8   // Exterior Gateway Protocol     RFC 888
	IPSetPortRangeIGP              ipsetProtoEnum = 9   // Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP))
	IPSetPortRangeBBN_RCC_MON      ipsetProtoEnum = 10  // BBN RCC Monitoring
	IPSetPortRangeNVP_II           ipsetProtoEnum = 11  // Network Voice Protocol     RFC 741
	IPSetPortRangePUP              ipsetProtoEnum = 12  // Xerox PUP
	IPSetPortRangeARGUS            ipsetProtoEnum = 13  // ARGUS
	IPSetPortRangeEMCON            ipsetProtoEnum = 14  // EMCON
	IPSetPortRangeXNET             ipsetProtoEnum = 15  // Cross Net Debugger     IEN 158
	IPSetPortRangeCHAOS            ipsetProtoEnum = 16  // Chaos
	IPSetPortRangeUDP              ipsetProtoEnum = 17  // User Datagram Protocol     RFC 768
	IPSetPortRangeMUX              ipsetProtoEnum = 18  // Multiplexing     IEN 90
	IPSetPortRangeDCN_MEAS         ipsetProtoEnum = 19  // DCN Measurement Subsystems
	IPSetPortRangeHMP              ipsetProtoEnum = 20  // Host Monitoring Protocol     RFC 869
	IPSetPortRangePRM              ipsetProtoEnum = 21  // Packet Radio Measurement
	IPSetPortRangeXNS_IDP          ipsetProtoEnum = 22  // XEROX NS IDP
	IPSetPortRangeTRUNK_1          ipsetProtoEnum = 23  // Trunk-1
	IPSetPortRangeTRUNK_2          ipsetProtoEnum = 24  // Trunk-2
	IPSetPortRangeLEAF_1           ipsetProtoEnum = 25  // Leaf-1
	IPSetPortRangeLEAF_2           ipsetProtoEnum = 26  // Leaf-2
	IPSetPortRangeRDP              ipsetProtoEnum = 27  // Reliable Data Protocol     RFC 908
	IPSetPortRangeIRTP             ipsetProtoEnum = 28  // Internet Reliable Transaction Protocol     RFC 938
	IPSetPortRangeISO_TP4          ipsetProtoEnum = 29  // ISO Transport Protocol Class 4     RFC 905
	IPSetPortRangeNETBLT           ipsetProtoEnum = 30  // Bulk Data Transfer Protocol     RFC 998
	IPSetPortRangeMFE_NSP          ipsetProtoEnum = 31  // MFE Network Services Protocol
	IPSetPortRangeMERIT_INP        ipsetProtoEnum = 32  // MERIT Internodal Protocol
	IPSetPortRangeDCCP             ipsetProtoEnum = 33  // Datagram Congestion Control Protocol     RFC 4340
	IPSetPortRangeThirdPC          ipsetProtoEnum = 34  // Third Party Connect Protocol
	IPSetPortRangeIDPR             ipsetProtoEnum = 35  // Inter-Domain Policy Routing Protocol     RFC 1479
	IPSetPortRangeXTP              ipsetProtoEnum = 36  // Xpress Transport Protocol
	IPSetPortRangeDDP              ipsetProtoEnum = 37  // Datagram Delivery Protocol
	IPSetPortRangeIDPR_CMTP        ipsetProtoEnum = 38  // IDPR Control Message Transport Protocol
	IPSetPortRangeTPPP             ipsetProtoEnum = 39  // TP++ Transport Protocol
	IPSetPortRangeIL               ipsetProtoEnum = 40  // IL Transport Protocol
	IPSetPortRangeIPv6             ipsetProtoEnum = 41  // IPv6 Encapsulation     RFC 2473
	IPSetPortRangeSDRP             ipsetProtoEnum = 42  // Source Demand Routing Protocol     RFC 1940
	IPSetPortRangeIPv6_Route       ipsetProtoEnum = 43  // Routing Header for IPv6     RFC 8200
	IPSetPortRangeIPv6_Frag        ipsetProtoEnum = 44  // Fragment Header for IPv6     RFC 8200
	IPSetPortRangeIDRP             ipsetProtoEnum = 45  // Inter-Domain Routing Protocol
	IPSetPortRangeRSVP             ipsetProtoEnum = 46  // Resource Reservation Protocol     RFC 2205
	IPSetPortRangeGREs             ipsetProtoEnum = 47  // Generic Routing Encapsulation     RFC 2784, RFC 2890
	IPSetPortRangeDSR              ipsetProtoEnum = 48  // Dynamic Source Routing Protocol     RFC 4728
	IPSetPortRangeBNA              ipsetProtoEnum = 49  // Burroughs Network Architecture
	IPSetPortRangeESP              ipsetProtoEnum = 50  // Encapsulating Security Payload     RFC 4303
	IPSetPortRangeAH               ipsetProtoEnum = 51  // Authentication Header     RFC 4302
	IPSetPortRangeI_NLSP           ipsetProtoEnum = 52  // Integrated Net Layer Security Protocol     TUBA
	IPSetPortRangeSWIPE            ipsetProtoEnum = 53  // SwIPe     IP with Encryption
	IPSetPortRangeNARP             ipsetProtoEnum = 54  // NBMA Address Resolution Protocol     RFC 1735
	IPSetPortRangeMOBILE           ipsetProtoEnum = 55  // IP Mobility (Min Encap)     RFC 2004
	IPSetPortRangeTLSP             ipsetProtoEnum = 56  // Transport Layer Security Protocol (using Kryptonet key management)
	IPSetPortRangeSKIP             ipsetProtoEnum = 57  // Simple Key-Management for Internet Protocol     RFC 2356
	IPSetPortRangeIPv6_ICMP        ipsetProtoEnum = 58  // ICMP for IPv6     RFC 4443, RFC 4884
	IPSetPortRangeIPv6_NoNxt       ipsetProtoEnum = 59  // No Next Header for IPv6     RFC 8200
	IPSetPortRangeIPv6_Opts        ipsetProtoEnum = 60  // Destination Options for IPv6     RFC 8200
	IPSetPortRangeAnyHostInternal  ipsetProtoEnum = 61  // Any host internal protocol
	IPSetPortRangeCFTP             ipsetProtoEnum = 62  // CFTP
	IPSetPortRangeAnyLocalNetwork  ipsetProtoEnum = 63  // Any local network
	IPSetPortRangeSAT_EXPAK        ipsetProtoEnum = 64  // SATNET and Backroom EXPAK
	IPSetPortRangeKRYPTOLAN        ipsetProtoEnum = 65  // Kryptolan
	IPSetPortRangeRVD              ipsetProtoEnum = 66  // MIT Remote Virtual Disk Protocol
	IPSetPortRangeIPPC             ipsetProtoEnum = 67  // Internet Pluribus Packet Core
	IPSetPortRangeAnyDistributedFS ipsetProtoEnum = 68  // Any distributed file system
	IPSetPortRangeSAT_MON          ipsetProtoEnum = 69  // SATNET Monitoring
	IPSetPortRangeVISA             ipsetProtoEnum = 70  // VISA Protocol
	IPSetPortRangeIPCU             ipsetProtoEnum = 71  // Internet Packet Core Utility
	IPSetPortRangeCPNX             ipsetProtoEnum = 72  // Computer Protocol Network Executive
	IPSetPortRangeCPHB             ipsetProtoEnum = 73  // Computer Protocol Heart Beat
	IPSetPortRangeWSN              ipsetProtoEnum = 74  // Wang Span Network
	IPSetPortRangePVP              ipsetProtoEnum = 75  // Packet Video Protocol
	IPSetPortRangeBR_SAT_MON       ipsetProtoEnum = 76  // Backroom SATNET Monitoring
	IPSetPortRangeSUN_ND           ipsetProtoEnum = 77  // SUN ND PROTOCOL-Temporary
	IPSetPortRangeWB_MON           ipsetProtoEnum = 78  // WIDEBAND Monitoring
	IPSetPortRangeWB_EXPAK         ipsetProtoEnum = 79  // WIDEBAND EXPAK
	IPSetPortRangeISO_IP           ipsetProtoEnum = 80  // International Organization for Standardization Internet Protocol
	IPSetPortRangeVMTP             ipsetProtoEnum = 81  // Versatile Message Transaction Protocol     RFC 1045
	IPSetPortRangeSECURE_VMTP      ipsetProtoEnum = 82  // Secure Versatile Message Transaction Protocol     RFC 1045
	IPSetPortRangeVINES            ipsetProtoEnum = 83  // VINES
	IPSetPortRangeTTP              ipsetProtoEnum = 84  // TTP
	IPSetPortRangeNSFNET_IGP       ipsetProtoEnum = 85  // NSFNET-IGP
	IPSetPortRangeDGP              ipsetProtoEnum = 86  // Dissimilar Gateway Protocol
	IPSetPortRangeTCF              ipsetProtoEnum = 87  // TCF
	IPSetPortRangeEIGRP            ipsetProtoEnum = 88  // EIGRP
	IPSetPortRangeOSPF             ipsetProtoEnum = 89  // Open Shortest Path First     RFC 1583
	IPSetPortRangeSprite_RPC       ipsetProtoEnum = 90  // Sprite RPC Protocol
	IPSetPortRangeLARP             ipsetProtoEnum = 91  // Locus Address Resolution Protocol
	IPSetPortRangeMTP              ipsetProtoEnum = 92  // Multicast Transport Protocol
	IPSetPortRangeAX_25            ipsetProtoEnum = 93  // AX.25
	IPSetPortRangeOS               ipsetProtoEnum = 94  // KA9Q NOS compatible IP over IP tunneling
	IPSetPortRangeMICP             ipsetProtoEnum = 95  // Mobile Internetworking Control Protocol
	IPSetPortRangeSCC_SP           ipsetProtoEnum = 96  // Semaphore Communications Sec. Pro
	IPSetPortRangeETHERIP          ipsetProtoEnum = 97  // Ethernet-within-IP Encapsulation     RFC 3378
	IPSetPortRangeENCAP            ipsetProtoEnum = 98  // Encapsulation Header     RFC 1241
	IPSetPortRangeAnyPrivateEnc    ipsetProtoEnum = 99  // Any private encryption scheme
	IPSetPortRangeGMTP             ipsetProtoEnum = 100 // GMTP
	IPSetPortRangeIFMP             ipsetProtoEnum = 101 // Ipsilon Flow Management Protocol
	IPSetPortRangePNNI             ipsetProtoEnum = 102 // PNNI over IP
	IPSetPortRangePIM              ipsetProtoEnum = 103 // Protocol Independent Multicast
	IPSetPortRangeARIS             ipsetProtoEnum = 104 // IBM's ARIS (Aggregate Route IP Switching) Protocol
	IPSetPortRangeSCPS             ipsetProtoEnum = 105 // SCPS (Space Communications Protocol Standards)     SCPS-TP[2]
	IPSetPortRangeQNX              ipsetProtoEnum = 106 // QNX
	IPSetPortRangeAN               ipsetProtoEnum = 107 // Active Networks
	IPSetPortRangeIPComp           ipsetProtoEnum = 108 // IP Payload Compression Protocol     RFC 3173
	IPSetPortRangeSNP              ipsetProtoEnum = 109 // Sitara Networks Protocol
	IPSetPortRangeCompaq_Peer      ipsetProtoEnum = 110 // Compaq Peer Protocol
	IPSetPortRangeIPX_in_IP        ipsetProtoEnum = 111 // IPX in IP
	IPSetPortRangeVRRP             ipsetProtoEnum = 112 // Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)     VRRP:RFC 3768
	IPSetPortRangePGM              ipsetProtoEnum = 113 // PGM Reliable Transport Protocol     RFC 3208
	IPSetPortRangeAnyZeroHop       ipsetProtoEnum = 114 // Any 0-hop protocol
	IPSetPortRangeL2TP             ipsetProtoEnum = 115 // Layer Two Tunneling Protocol Version 3     RFC 3931
	IPSetPortRangeDDX              ipsetProtoEnum = 116 // D-II Data Exchange (DDX)
	IPSetPortRangeIATP             ipsetProtoEnum = 117 // Interactive Agent Transfer Protocol
	IPSetPortRangeSTP              ipsetProtoEnum = 118 // Schedule Transfer Protocol
	IPSetPortRangeSRP              ipsetProtoEnum = 119 // SpectraLink Radio Protocol
	IPSetPortRangeUTI              ipsetProtoEnum = 120 // Universal Transport Interface Protocol
	IPSetPortRangeSMP              ipsetProtoEnum = 121 // Simple Message Protocol
	IPSetPortRangeSM               ipsetProtoEnum = 122 // Simple Multicast Protocol     draft-perlman-simple-multicast-03
	IPSetPortRangePTP              ipsetProtoEnum = 123 // Performance Transparency Protocol
	IPSetPortRangeIS_ISOverIPv4    ipsetProtoEnum = 124 // Intermediate System to Intermediate System (IS-IS) Protocol over IPv4     RFC 1142 and RFC 1195
	IPSetPortRangeFIRE             ipsetProtoEnum = 125 // Flexible Intra-AS Routing Environment
	IPSetPortRangeCRTP             ipsetProtoEnum = 126 // Combat Radio Transport Protocol
	IPSetPortRangeCRUDP            ipsetProtoEnum = 127 // Combat Radio User Datagram
	IPSetPortRangeSSCOPMCE         ipsetProtoEnum = 128 // Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment     ITU-T Q.2111 (1999)
	IPSetPortRangeIPLT             ipsetProtoEnum = 129 //
	IPSetPortRangeSPS              ipsetProtoEnum = 130 // Secure Packet Shield
	IPSetPortRangePIPE             ipsetProtoEnum = 131 // Private IP Encapsulation within IP     Expired I-D draft-petri-mobileip-pipe-00.txt
	IPSetPortRangeSCTP             ipsetProtoEnum = 132 // Stream Control Transmission Protocol     RFC 4960
	IPSetPortRangeFC               ipsetProtoEnum = 133 // Fibre Channel
	IPSetPortRangeRSVP_E2E_IGNORE  ipsetProtoEnum = 134 // Reservation Protocol (RSVP) End-to-End Ignore     RFC 3175
	IPSetPortRangeMobility         ipsetProtoEnum = 135 // Header     Mobility Extension Header for IPv6     RFC 6275
	IPSetPortRangeUDPLite          ipsetProtoEnum = 136 // Lightweight User Datagram Protocol     RFC 3828
	IPSetPortRangeMPLS_in_IP       ipsetProtoEnum = 137 // Multiprotocol Label Switching Encapsulated in IP     RFC 4023, RFC 5332
	IPSetPortRangemanet            ipsetProtoEnum = 138 // MANET Protocols     RFC 5498
	IPSetPortRangeHIP              ipsetProtoEnum = 139 // Host Identity Protocol     RFC 5201
	IPSetPortRangeShim6            ipsetProtoEnum = 140 // Site Multihoming by IPv6 Intermediation     RFC 5533
	IPSetPortRangeWESP             ipsetProtoEnum = 141 // Wrapped Encapsulating Security Payload     RFC 5840
	IPSetPortRangeROHC             ipsetProtoEnum = 142 // Robust Header Compression     RFC 5856
)

func ipsetProtoEnumFromByte(b uint8) ipsetProtoEnum {
	switch b {
	case 0:
		return IPSetPortRangeAny
	case 1:
		return IPSetPortRangeICMP
	case 2:
		return IPSetPortRangeIGMP
	case 3:
		return IPSetPortRangeGGP
	case 4:
		return IPSetPortRangeIP_in_IP
	case 5:
		return IPSetPortRangeST
	case 6:
		return IPSetPortRangeTCP
	case 7:
		return IPSetPortRangeCBT
	case 8:
		return IPSetPortRangeEGP
	case 9:
		return IPSetPortRangeIGP
	case 10:
		return IPSetPortRangeBBN_RCC_MON
	case 11:
		return IPSetPortRangeNVP_II
	case 12:
		return IPSetPortRangePUP
	case 13:
		return IPSetPortRangeARGUS
	case 14:
		return IPSetPortRangeEMCON
	case 15:
		return IPSetPortRangeXNET
	case 16:
		return IPSetPortRangeCHAOS
	case 17:
		return IPSetPortRangeUDP
	case 18:
		return IPSetPortRangeMUX
	case 19:
		return IPSetPortRangeDCN_MEAS
	case 20:
		return IPSetPortRangeHMP
	case 21:
		return IPSetPortRangePRM
	case 22:
		return IPSetPortRangeXNS_IDP
	case 23:
		return IPSetPortRangeTRUNK_1
	case 24:
		return IPSetPortRangeTRUNK_2
	case 25:
		return IPSetPortRangeLEAF_1
	case 26:
		return IPSetPortRangeLEAF_2
	case 27:
		return IPSetPortRangeRDP
	case 28:
		return IPSetPortRangeIRTP
	case 29:
		return IPSetPortRangeISO_TP4
	case 30:
		return IPSetPortRangeNETBLT
	case 31:
		return IPSetPortRangeMFE_NSP
	case 32:
		return IPSetPortRangeMERIT_INP
	case 33:
		return IPSetPortRangeDCCP
	case 34:
		return IPSetPortRangeThirdPC
	case 35:
		return IPSetPortRangeIDPR
	case 36:
		return IPSetPortRangeXTP
	case 37:
		return IPSetPortRangeDDP
	case 38:
		return IPSetPortRangeIDPR_CMTP
	case 39:
		return IPSetPortRangeTPPP
	case 40:
		return IPSetPortRangeIL
	case 41:
		return IPSetPortRangeIPv6
	case 42:
		return IPSetPortRangeSDRP
	case 43:
		return IPSetPortRangeIPv6_Route
	case 44:
		return IPSetPortRangeIPv6_Frag
	case 45:
		return IPSetPortRangeIDRP
	case 46:
		return IPSetPortRangeRSVP
	case 47:
		return IPSetPortRangeGREs
	case 48:
		return IPSetPortRangeDSR
	case 49:
		return IPSetPortRangeBNA
	case 50:
		return IPSetPortRangeESP
	case 51:
		return IPSetPortRangeAH
	case 52:
		return IPSetPortRangeI_NLSP
	case 53:
		return IPSetPortRangeSWIPE
	case 54:
		return IPSetPortRangeNARP
	case 55:
		return IPSetPortRangeMOBILE
	case 56:
		return IPSetPortRangeTLSP
	case 57:
		return IPSetPortRangeSKIP
	case 58:
		return IPSetPortRangeIPv6_ICMP
	case 59:
		return IPSetPortRangeIPv6_NoNxt
	case 60:
		return IPSetPortRangeIPv6_Opts
	case 61:
		return IPSetPortRangeAnyHostInternal
	case 62:
		return IPSetPortRangeCFTP
	case 63:
		return IPSetPortRangeAnyLocalNetwork
	case 64:
		return IPSetPortRangeSAT_EXPAK
	case 65:
		return IPSetPortRangeKRYPTOLAN
	case 66:
		return IPSetPortRangeRVD
	case 67:
		return IPSetPortRangeIPPC
	case 68:
		return IPSetPortRangeAnyDistributedFS
	case 69:
		return IPSetPortRangeSAT_MON
	case 70:
		return IPSetPortRangeVISA
	case 71:
		return IPSetPortRangeIPCU
	case 72:
		return IPSetPortRangeCPNX
	case 73:
		return IPSetPortRangeCPHB
	case 74:
		return IPSetPortRangeWSN
	case 75:
		return IPSetPortRangePVP
	case 76:
		return IPSetPortRangeBR_SAT_MON
	case 77:
		return IPSetPortRangeSUN_ND
	case 78:
		return IPSetPortRangeWB_MON
	case 79:
		return IPSetPortRangeWB_EXPAK
	case 80:
		return IPSetPortRangeISO_IP
	case 81:
		return IPSetPortRangeVMTP
	case 82:
		return IPSetPortRangeSECURE_VMTP
	case 83:
		return IPSetPortRangeVINES
	case 84:
		return IPSetPortRangeTTP
	case 85:
		return IPSetPortRangeNSFNET_IGP
	case 86:
		return IPSetPortRangeDGP
	case 87:
		return IPSetPortRangeTCF
	case 88:
		return IPSetPortRangeEIGRP
	case 89:
		return IPSetPortRangeOSPF
	case 90:
		return IPSetPortRangeSprite_RPC
	case 91:
		return IPSetPortRangeLARP
	case 92:
		return IPSetPortRangeMTP
	case 93:
		return IPSetPortRangeAX_25
	case 94:
		return IPSetPortRangeOS
	case 95:
		return IPSetPortRangeMICP
	case 96:
		return IPSetPortRangeSCC_SP
	case 97:
		return IPSetPortRangeETHERIP
	case 98:
		return IPSetPortRangeENCAP
	case 99:
		return IPSetPortRangeAnyPrivateEnc
	case 100:
		return IPSetPortRangeGMTP
	case 101:
		return IPSetPortRangeIFMP
	case 102:
		return IPSetPortRangePNNI
	case 103:
		return IPSetPortRangePIM
	case 104:
		return IPSetPortRangeARIS
	case 105:
		return IPSetPortRangeSCPS
	case 106:
		return IPSetPortRangeQNX
	case 107:
		return IPSetPortRangeAN
	case 108:
		return IPSetPortRangeIPComp
	case 109:
		return IPSetPortRangeSNP
	case 110:
		return IPSetPortRangeCompaq_Peer
	case 111:
		return IPSetPortRangeIPX_in_IP
	case 112:
		return IPSetPortRangeVRRP
	case 113:
		return IPSetPortRangePGM
	case 114:
		return IPSetPortRangeAnyZeroHop
	case 115:
		return IPSetPortRangeL2TP
	case 116:
		return IPSetPortRangeDDX
	case 117:
		return IPSetPortRangeIATP
	case 118:
		return IPSetPortRangeSTP
	case 119:
		return IPSetPortRangeSRP
	case 120:
		return IPSetPortRangeUTI
	case 121:
		return IPSetPortRangeSMP
	case 122:
		return IPSetPortRangeSM
	case 123:
		return IPSetPortRangePTP
	case 124:
		return IPSetPortRangeIS_ISOverIPv4
	case 125:
		return IPSetPortRangeFIRE
	case 126:
		return IPSetPortRangeCRTP
	case 127:
		return IPSetPortRangeCRUDP
	case 128:
		return IPSetPortRangeSSCOPMCE
	case 129:
		return IPSetPortRangeIPLT
	case 130:
		return IPSetPortRangeSPS
	case 131:
		return IPSetPortRangePIPE
	case 132:
		return IPSetPortRangeSCTP
	case 133:
		return IPSetPortRangeFC
	case 134:
		return IPSetPortRangeRSVP_E2E_IGNORE
	case 135:
		return IPSetPortRangeMobility
	case 136:
		return IPSetPortRangeUDPLite
	case 137:
		return IPSetPortRangeMPLS_in_IP
	case 138:
		return IPSetPortRangemanet
	case 139:
		return IPSetPortRangeHIP
	case 140:
		return IPSetPortRangeShim6
	case 141:
		return IPSetPortRangeWESP
	case 142:
		return IPSetPortRangeROHC
	default:
		panic(fmt.Errorf("Invalid IPSet family %d", b))
	}
}
