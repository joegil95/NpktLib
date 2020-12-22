/*
header tcpip.h
*/

// constantes generales

#define ETHERNET		0x0001	// valeur normalisee pour ethernet support */
#define TYPE_IP		0x0800
#define TYPE_ARP		0x0806

// Constantes ARP

#define REQUEST_ARP	0x0001	// demande ARP
#define ANSWER_ARP	0x0002	// reponse ARP

// constantes IP

#define PROT_ICMP	0x01	// protocole icmp
#define PROT_TCP	0x06	// protocole tcp
#define PROT_UDP	0x11	// protocole udp

// Constantes ICMP

#define	ANSWER_ICMP		0x00	// reponse echo
#define	REQUEST_ICMP	0x08	// demande echo


// structures

struct ADR_eth			/* adresse ethernet sur 6 octets */
	{
	__pragma(pack(push, 1)) 
	unsigned char oct[6];
	__pragma(pack(pop))
	};

struct ADR_ip			/* adresse ip sur 4 octets */
	{
	__pragma(pack(push, 1)) 
	unsigned char dec[4];
	__pragma(pack(pop))
	};

struct DTG_arp		// datagramme ARP
	{
	__pragma(pack(push, 1))			// packed struct (alignement)
	unsigned short hard;	
	unsigned short prot;
	unsigned char lgr_hard;
	unsigned char lgr_prot;
	unsigned short op;
	struct ADR_eth srce_eth;
	struct ADR_ip srce_ip;
	struct ADR_eth dest_eth;
	struct ADR_ip dest_ip;
	__pragma(pack(pop))
	};

struct DTG_icmp		// message ICMP de base
	{
	__pragma(pack(push, 1))			// packed struct (alignement)
	unsigned char type;
	unsigned char code;
	unsigned short check;
	unsigned short ident;
	unsigned short seq;			
	unsigned char data[1500];
	__pragma(pack(pop))
	};

struct DTG_ip		// datagramme IP de base
	{
	__pragma(pack(push, 1)) 
	unsigned char vers_lgr;
	unsigned char prior;
	unsigned short lgr_tot;	
	unsigned short rand_id;
	unsigned short frag;
	unsigned char life;
	unsigned char prot;
	unsigned short check;
	struct ADR_ip srce_ip;
	struct ADR_ip dest_ip;
	struct DTG_icmp data;		// cas particulier
	__pragma(pack(pop))
	};

union PACK		// datagrameme ARP ou IP au choix
	{
	__pragma(pack(push, 1)) 
	struct DTG_arp dtg_arp;
	struct DTG_ip dtg_ip;
	__pragma(pack(pop))
	};



struct TRAME_eth	// trame Ethernet
  	{
	__pragma(pack(push, 1)) 
  	struct ADR_eth dest;
  	struct ADR_eth srce;
  	unsigned short type;

	union PACK data;
	__pragma(pack(pop))
  	};


