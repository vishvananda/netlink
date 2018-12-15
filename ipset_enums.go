package netlink

import "fmt"

type IpsetTypeEnum string

func (t IpsetTypeEnum) toString() string {
	return string(t)
}

// possible IPSet types
const (
	IPSetHashIP         IpsetTypeEnum = "hash:ip"
	IPSetBitmapIP       IpsetTypeEnum = "bitmap:ip"
	IPSetBitmapIPMac    IpsetTypeEnum = "bitmap:ip,mac"
	IPSetBitmapPort     IpsetTypeEnum = "bitmap:port"
	IPSetHashMac        IpsetTypeEnum = "hash:mac"
	IPSetHashNet        IpsetTypeEnum = "hash:net"
	IPSetHashNetNet     IpsetTypeEnum = "hash:net,net"
	IPSetHashIPPort     IpsetTypeEnum = "hash:ip,port"
	IPSetHashNetPort    IpsetTypeEnum = "hash:net,port"
	IPSetHashIPPortIP   IpsetTypeEnum = "hash:ip,port,ip"
	IPSetHashIPPortNet  IpsetTypeEnum = "hash:ip,port,net"
	IPSetHashIPMark     IpsetTypeEnum = "hash:ip,mark"
	IPSetHashNetPortNet IpsetTypeEnum = "hash:net,port,net"
	IPSetHashNetIface   IpsetTypeEnum = "hash:net,iface"
	IPSetListSet        IpsetTypeEnum = "list:set"
)

func IpsetTypeEnumFromString(str string) IpsetTypeEnum {
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

type IpsetFamilyEnum uint8

func (f IpsetFamilyEnum) toUint8() uint8 {
	return uint8(f)
}

// http://git.netfilter.org/ipset/tree/include/libipset/nfproto.h
const (
	NFPROTO_IPV4 IpsetFamilyEnum = 2
	NFPROTO_IPV6 IpsetFamilyEnum = 10
)

func IpsetFamilyEnumFromByte(b uint8) IpsetFamilyEnum {
	switch b {
	case 2:
		return NFPROTO_IPV4
	case 10:
		return NFPROTO_IPV6
	default:
		panic(fmt.Errorf("Invalid IPSet family %d", b))
	}
}

type IpsetProtoEnum uint8

// possible IPSet protocols
const (
	IPSetPortRangeAny              IpsetProtoEnum = 0
	IPSetPortRangeICMP             IpsetProtoEnum = 1   // Internet Control Message Protocol     RFC 792
	IPSetPortRangeIGMP             IpsetProtoEnum = 2   // Internet Group Management Protocol     RFC 1112
	IPSetPortRangeGGP              IpsetProtoEnum = 3   // Gateway-to-Gateway Protocol     RFC 823
	IPSetPortRangeIP_in_IP         IpsetProtoEnum = 4   // IP in IP (encapsulation)     RFC 2003
	IPSetPortRangeST               IpsetProtoEnum = 5   // Internet Stream Protocol     RFC 1190, RFC 1819
	IPSetPortRangeTCP              IpsetProtoEnum = 6   // Transmission Control Protocol     RFC 793
	IPSetPortRangeCBT              IpsetProtoEnum = 7   // Core-based trees     RFC 2189
	IPSetPortRangeEGP              IpsetProtoEnum = 8   // Exterior Gateway Protocol     RFC 888
	IPSetPortRangeIGP              IpsetProtoEnum = 9   // Interior Gateway Protocol (any private interior gateway (used by Cisco for their IGRP))
	IPSetPortRangeBBN_RCC_MON      IpsetProtoEnum = 10  // BBN RCC Monitoring
	IPSetPortRangeNVP_II           IpsetProtoEnum = 11  // Network Voice Protocol     RFC 741
	IPSetPortRangePUP              IpsetProtoEnum = 12  // Xerox PUP
	IPSetPortRangeARGUS            IpsetProtoEnum = 13  // ARGUS
	IPSetPortRangeEMCON            IpsetProtoEnum = 14  // EMCON
	IPSetPortRangeXNET             IpsetProtoEnum = 15  // Cross Net Debugger     IEN 158
	IPSetPortRangeCHAOS            IpsetProtoEnum = 16  // Chaos
	IPSetPortRangeUDP              IpsetProtoEnum = 17  // User Datagram Protocol     RFC 768
	IPSetPortRangeMUX              IpsetProtoEnum = 18  // Multiplexing     IEN 90
	IPSetPortRangeDCN_MEAS         IpsetProtoEnum = 19  // DCN Measurement Subsystems
	IPSetPortRangeHMP              IpsetProtoEnum = 20  // Host Monitoring Protocol     RFC 869
	IPSetPortRangePRM              IpsetProtoEnum = 21  // Packet Radio Measurement
	IPSetPortRangeXNS_IDP          IpsetProtoEnum = 22  // XEROX NS IDP
	IPSetPortRangeTRUNK_1          IpsetProtoEnum = 23  // Trunk-1
	IPSetPortRangeTRUNK_2          IpsetProtoEnum = 24  // Trunk-2
	IPSetPortRangeLEAF_1           IpsetProtoEnum = 25  // Leaf-1
	IPSetPortRangeLEAF_2           IpsetProtoEnum = 26  // Leaf-2
	IPSetPortRangeRDP              IpsetProtoEnum = 27  // Reliable Data Protocol     RFC 908
	IPSetPortRangeIRTP             IpsetProtoEnum = 28  // Internet Reliable Transaction Protocol     RFC 938
	IPSetPortRangeISO_TP4          IpsetProtoEnum = 29  // ISO Transport Protocol Class 4     RFC 905
	IPSetPortRangeNETBLT           IpsetProtoEnum = 30  // Bulk Data Transfer Protocol     RFC 998
	IPSetPortRangeMFE_NSP          IpsetProtoEnum = 31  // MFE Network Services Protocol
	IPSetPortRangeMERIT_INP        IpsetProtoEnum = 32  // MERIT Internodal Protocol
	IPSetPortRangeDCCP             IpsetProtoEnum = 33  // Datagram Congestion Control Protocol     RFC 4340
	IPSetPortRangeThirdPC          IpsetProtoEnum = 34  // Third Party Connect Protocol
	IPSetPortRangeIDPR             IpsetProtoEnum = 35  // Inter-Domain Policy Routing Protocol     RFC 1479
	IPSetPortRangeXTP              IpsetProtoEnum = 36  // Xpress Transport Protocol
	IPSetPortRangeDDP              IpsetProtoEnum = 37  // Datagram Delivery Protocol
	IPSetPortRangeIDPR_CMTP        IpsetProtoEnum = 38  // IDPR Control Message Transport Protocol
	IPSetPortRangeTPPP             IpsetProtoEnum = 39  // TP++ Transport Protocol
	IPSetPortRangeIL               IpsetProtoEnum = 40  // IL Transport Protocol
	IPSetPortRangeIPv6             IpsetProtoEnum = 41  // IPv6 Encapsulation     RFC 2473
	IPSetPortRangeSDRP             IpsetProtoEnum = 42  // Source Demand Routing Protocol     RFC 1940
	IPSetPortRangeIPv6_Route       IpsetProtoEnum = 43  // Routing Header for IPv6     RFC 8200
	IPSetPortRangeIPv6_Frag        IpsetProtoEnum = 44  // Fragment Header for IPv6     RFC 8200
	IPSetPortRangeIDRP             IpsetProtoEnum = 45  // Inter-Domain Routing Protocol
	IPSetPortRangeRSVP             IpsetProtoEnum = 46  // Resource Reservation Protocol     RFC 2205
	IPSetPortRangeGREs             IpsetProtoEnum = 47  // Generic Routing Encapsulation     RFC 2784, RFC 2890
	IPSetPortRangeDSR              IpsetProtoEnum = 48  // Dynamic Source Routing Protocol     RFC 4728
	IPSetPortRangeBNA              IpsetProtoEnum = 49  // Burroughs Network Architecture
	IPSetPortRangeESP              IpsetProtoEnum = 50  // Encapsulating Security Payload     RFC 4303
	IPSetPortRangeAH               IpsetProtoEnum = 51  // Authentication Header     RFC 4302
	IPSetPortRangeI_NLSP           IpsetProtoEnum = 52  // Integrated Net Layer Security Protocol     TUBA
	IPSetPortRangeSWIPE            IpsetProtoEnum = 53  // SwIPe     IP with Encryption
	IPSetPortRangeNARP             IpsetProtoEnum = 54  // NBMA Address Resolution Protocol     RFC 1735
	IPSetPortRangeMOBILE           IpsetProtoEnum = 55  // IP Mobility (Min Encap)     RFC 2004
	IPSetPortRangeTLSP             IpsetProtoEnum = 56  // Transport Layer Security Protocol (using Kryptonet key management)
	IPSetPortRangeSKIP             IpsetProtoEnum = 57  // Simple Key-Management for Internet Protocol     RFC 2356
	IPSetPortRangeIPv6_ICMP        IpsetProtoEnum = 58  // ICMP for IPv6     RFC 4443, RFC 4884
	IPSetPortRangeIPv6_NoNxt       IpsetProtoEnum = 59  // No Next Header for IPv6     RFC 8200
	IPSetPortRangeIPv6_Opts        IpsetProtoEnum = 60  // Destination Options for IPv6     RFC 8200
	IPSetPortRangeAnyHostInternal  IpsetProtoEnum = 61  // Any host internal protocol
	IPSetPortRangeCFTP             IpsetProtoEnum = 62  // CFTP
	IPSetPortRangeAnyLocalNetwork  IpsetProtoEnum = 63  // Any local network
	IPSetPortRangeSAT_EXPAK        IpsetProtoEnum = 64  // SATNET and Backroom EXPAK
	IPSetPortRangeKRYPTOLAN        IpsetProtoEnum = 65  // Kryptolan
	IPSetPortRangeRVD              IpsetProtoEnum = 66  // MIT Remote Virtual Disk Protocol
	IPSetPortRangeIPPC             IpsetProtoEnum = 67  // Internet Pluribus Packet Core
	IPSetPortRangeAnyDistributedFS IpsetProtoEnum = 68  // Any distributed file system
	IPSetPortRangeSAT_MON          IpsetProtoEnum = 69  // SATNET Monitoring
	IPSetPortRangeVISA             IpsetProtoEnum = 70  // VISA Protocol
	IPSetPortRangeIPCU             IpsetProtoEnum = 71  // Internet Packet Core Utility
	IPSetPortRangeCPNX             IpsetProtoEnum = 72  // Computer Protocol Network Executive
	IPSetPortRangeCPHB             IpsetProtoEnum = 73  // Computer Protocol Heart Beat
	IPSetPortRangeWSN              IpsetProtoEnum = 74  // Wang Span Network
	IPSetPortRangePVP              IpsetProtoEnum = 75  // Packet Video Protocol
	IPSetPortRangeBR_SAT_MON       IpsetProtoEnum = 76  // Backroom SATNET Monitoring
	IPSetPortRangeSUN_ND           IpsetProtoEnum = 77  // SUN ND PROTOCOL-Temporary
	IPSetPortRangeWB_MON           IpsetProtoEnum = 78  // WIDEBAND Monitoring
	IPSetPortRangeWB_EXPAK         IpsetProtoEnum = 79  // WIDEBAND EXPAK
	IPSetPortRangeISO_IP           IpsetProtoEnum = 80  // International Organization for Standardization Internet Protocol
	IPSetPortRangeVMTP             IpsetProtoEnum = 81  // Versatile Message Transaction Protocol     RFC 1045
	IPSetPortRangeSECURE_VMTP      IpsetProtoEnum = 82  // Secure Versatile Message Transaction Protocol     RFC 1045
	IPSetPortRangeVINES            IpsetProtoEnum = 83  // VINES
	IPSetPortRangeTTP              IpsetProtoEnum = 84  // TTP
	IPSetPortRangeNSFNET_IGP       IpsetProtoEnum = 85  // NSFNET-IGP
	IPSetPortRangeDGP              IpsetProtoEnum = 86  // Dissimilar Gateway Protocol
	IPSetPortRangeTCF              IpsetProtoEnum = 87  // TCF
	IPSetPortRangeEIGRP            IpsetProtoEnum = 88  // EIGRP
	IPSetPortRangeOSPF             IpsetProtoEnum = 89  // Open Shortest Path First     RFC 1583
	IPSetPortRangeSprite_RPC       IpsetProtoEnum = 90  // Sprite RPC Protocol
	IPSetPortRangeLARP             IpsetProtoEnum = 91  // Locus Address Resolution Protocol
	IPSetPortRangeMTP              IpsetProtoEnum = 92  // Multicast Transport Protocol
	IPSetPortRangeAX_25            IpsetProtoEnum = 93  // AX.25
	IPSetPortRangeOS               IpsetProtoEnum = 94  // KA9Q NOS compatible IP over IP tunneling
	IPSetPortRangeMICP             IpsetProtoEnum = 95  // Mobile Internetworking Control Protocol
	IPSetPortRangeSCC_SP           IpsetProtoEnum = 96  // Semaphore Communications Sec. Pro
	IPSetPortRangeETHERIP          IpsetProtoEnum = 97  // Ethernet-within-IP Encapsulation     RFC 3378
	IPSetPortRangeENCAP            IpsetProtoEnum = 98  // Encapsulation Header     RFC 1241
	IPSetPortRangeAnyPrivateEnc    IpsetProtoEnum = 99  // Any private encryption scheme
	IPSetPortRangeGMTP             IpsetProtoEnum = 100 // GMTP
	IPSetPortRangeIFMP             IpsetProtoEnum = 101 // Ipsilon Flow Management Protocol
	IPSetPortRangePNNI             IpsetProtoEnum = 102 // PNNI over IP
	IPSetPortRangePIM              IpsetProtoEnum = 103 // Protocol Independent Multicast
	IPSetPortRangeARIS             IpsetProtoEnum = 104 // IBM's ARIS (Aggregate Route IP Switching) Protocol
	IPSetPortRangeSCPS             IpsetProtoEnum = 105 // SCPS (Space Communications Protocol Standards)     SCPS-TP[2]
	IPSetPortRangeQNX              IpsetProtoEnum = 106 // QNX
	IPSetPortRangeAN               IpsetProtoEnum = 107 // Active Networks
	IPSetPortRangeIPComp           IpsetProtoEnum = 108 // IP Payload Compression Protocol     RFC 3173
	IPSetPortRangeSNP              IpsetProtoEnum = 109 // Sitara Networks Protocol
	IPSetPortRangeCompaq_Peer      IpsetProtoEnum = 110 // Compaq Peer Protocol
	IPSetPortRangeIPX_in_IP        IpsetProtoEnum = 111 // IPX in IP
	IPSetPortRangeVRRP             IpsetProtoEnum = 112 // Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned)     VRRP:RFC 3768
	IPSetPortRangePGM              IpsetProtoEnum = 113 // PGM Reliable Transport Protocol     RFC 3208
	IPSetPortRangeAnyZeroHop       IpsetProtoEnum = 114 // Any 0-hop protocol
	IPSetPortRangeL2TP             IpsetProtoEnum = 115 // Layer Two Tunneling Protocol Version 3     RFC 3931
	IPSetPortRangeDDX              IpsetProtoEnum = 116 // D-II Data Exchange (DDX)
	IPSetPortRangeIATP             IpsetProtoEnum = 117 // Interactive Agent Transfer Protocol
	IPSetPortRangeSTP              IpsetProtoEnum = 118 // Schedule Transfer Protocol
	IPSetPortRangeSRP              IpsetProtoEnum = 119 // SpectraLink Radio Protocol
	IPSetPortRangeUTI              IpsetProtoEnum = 120 // Universal Transport Interface Protocol
	IPSetPortRangeSMP              IpsetProtoEnum = 121 // Simple Message Protocol
	IPSetPortRangeSM               IpsetProtoEnum = 122 // Simple Multicast Protocol     draft-perlman-simple-multicast-03
	IPSetPortRangePTP              IpsetProtoEnum = 123 // Performance Transparency Protocol
	IPSetPortRangeIS_ISOverIPv4    IpsetProtoEnum = 124 // Intermediate System to Intermediate System (IS-IS) Protocol over IPv4     RFC 1142 and RFC 1195
	IPSetPortRangeFIRE             IpsetProtoEnum = 125 // Flexible Intra-AS Routing Environment
	IPSetPortRangeCRTP             IpsetProtoEnum = 126 // Combat Radio Transport Protocol
	IPSetPortRangeCRUDP            IpsetProtoEnum = 127 // Combat Radio User Datagram
	IPSetPortRangeSSCOPMCE         IpsetProtoEnum = 128 // Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment     ITU-T Q.2111 (1999)
	IPSetPortRangeIPLT             IpsetProtoEnum = 129 //
	IPSetPortRangeSPS              IpsetProtoEnum = 130 // Secure Packet Shield
	IPSetPortRangePIPE             IpsetProtoEnum = 131 // Private IP Encapsulation within IP     Expired I-D draft-petri-mobileip-pipe-00.txt
	IPSetPortRangeSCTP             IpsetProtoEnum = 132 // Stream Control Transmission Protocol     RFC 4960
	IPSetPortRangeFC               IpsetProtoEnum = 133 // Fibre Channel
	IPSetPortRangeRSVP_E2E_IGNORE  IpsetProtoEnum = 134 // Reservation Protocol (RSVP) End-to-End Ignore     RFC 3175
	IPSetPortRangeMobility         IpsetProtoEnum = 135 // Header     Mobility Extension Header for IPv6     RFC 6275
	IPSetPortRangeUDPLite          IpsetProtoEnum = 136 // Lightweight User Datagram Protocol     RFC 3828
	IPSetPortRangeMPLS_in_IP       IpsetProtoEnum = 137 // Multiprotocol Label Switching Encapsulated in IP     RFC 4023, RFC 5332
	IPSetPortRangemanet            IpsetProtoEnum = 138 // MANET Protocols     RFC 5498
	IPSetPortRangeHIP              IpsetProtoEnum = 139 // Host Identity Protocol     RFC 5201
	IPSetPortRangeShim6            IpsetProtoEnum = 140 // Site Multihoming by IPv6 Intermediation     RFC 5533
	IPSetPortRangeWESP             IpsetProtoEnum = 141 // Wrapped Encapsulating Security Payload     RFC 5840
	IPSetPortRangeROHC             IpsetProtoEnum = 142 // Robust Header Compression     RFC 5856
)

func IpsetProtoEnumFromByte(b uint8) IpsetProtoEnum {
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
