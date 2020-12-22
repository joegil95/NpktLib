/*
 * Librairie de type "Packet Driver" NpktLib basée sur Npcap (Windows x86 & x64)
 * A compiler sous VC++
 * @(#) JG 2020
 *
 */

#include "tcpip.h"

#include "NpktLib.h"


static struct ADR_eth BROADCAST= {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static struct ADR_eth NUL_ETH= {0, 0, 0, 0, 0, 0};
static struct ADR_ip NUL_IP= {0, 0, 0, 0};


// Fonction a usage interne
BOOL Npkt_LoadDlls()
	{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) 
		{
        printf("Error in GetSystemDirectory: %x\n", GetLastError());
        return FALSE;
		}
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) 
		{
        printf("Error in SetDllDirectory: %x\n", GetLastError());
        return FALSE;
		}

    return TRUE;
	}


// Ouverture d'un packet driver sur une interface reseau
// num= numero de l'interface dans la liste constituee par la fonction
// num= 1 convient en general
// flag= PCAP_OPENFLAG_PROMISCUOUS pour capturer tout le trafic reseau
// flag= 0 sinon
// Retourne un handle (pointeur) ou NULL si erreur

Npkt_Handle Npkt_Open(int num, u_long flag)
	{
	Npkt_Handle hp= NULL;
	pcap_if_t * devs, * d;
	pcap_t * p;
	char * pcap_version;
	char errbuf[PCAP_ERRBUF_SIZE];
	int n= 0;

	// Load Npcap Dlls
    if (! Npkt_LoadDlls())
	    {
        printf("error in Npkt_LoadDlls()\n");
        return NULL;
		}

	pcap_version = pcap_lib_version();
    printf("%s\n\n", pcap_version);

	// List interfaces
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &devs, errbuf) == -1)
		{
		printf("Error in pcap_findalldevs(): %s\n", errbuf);
		return NULL;
		}

	// Print the list of interfaces (network adapters)
	printf("Available network interfaces:\n");
	for(d= devs ; d ; d=d->next)
		{
		printf("# %d:\t%s\n", ++n, d->name);
		if (d->description)
			printf("\t(%s)\n", d->description);
		else
			printf("\t(No description)\n");
		}
		
	if(n == 0)
		{
		printf("No interface found ! Make sure Npcap driver is installed.\n");
		return NULL;
		}
	else
		printf("\n");

	// Jump to the selected adapter d
	for (d= devs, n=0; n < num-1 ; d= d->next, n++);	

	// Open the device with 100 ms timeout
	printf("Opening interface # %d...\n\n", num);
	p= pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, errbuf);
	if (p == NULL)
		{
		printf("Unable to open adapter %s\n", d->name);
		// Free device list
		pcap_freealldevs(devs);
		return NULL;
		}

	// Allocate memory for Handle if everything is OK
	hp= (Npkt_Handle) Malloc(sizeof (Npkt_Struct));
	
	hp->devs = devs;
	hp->ifhd= d;
	hp->pkthd= p;

	return hp;
	}


// Recuperation de l'adresse Mac d'une interface Ethernet
// hp= Handle de l'interface ouverte
// adr_eth= structure qui recevra l'adresse
// Retourne 0 si OK

int Npkt_GetMacAddress(Npkt_Handle hp, struct ADR_eth * adr_eth)
	{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD RetVal = 0;
	ULONG ulOutBufLen= 0;
    UINT i;
	char * pos1, * pos2;
	char name[256]= "";

	* adr_eth= NUL_ETH;
	if (hp == NULL) return 1;

	// Nom Windows de l'interface entre { }
	pos1= strchr(hp->ifhd->name, '{');
	pos2= strrchr(hp->ifhd->name, '}');
	if ((pos1 != NULL) && (pos2 != NULL))
		strncpy(name, pos1, (int) (pos2-pos1) +1);
	else 
		return 2;

    ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) Malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) 
		{
        printf("Error allocating memory for GetAdaptersinfo()\n");
        return 3;
		}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
		{
        Free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) Malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) 
			{
            printf("Error allocating memory for GetAdaptersinfo()\n");
            return 3;
			}
		}

    if ((RetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
		{
        pAdapter = pAdapterInfo;

        while (pAdapter) 
			{
			if ((strcmp(pAdapter->AdapterName, name) == 0) && (pAdapter->Type == MIB_IF_TYPE_ETHERNET))
				{
				printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
				printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
				printf("\tAdapter Addr: \t");
            
				for (i = 0; i < pAdapter->AddressLength; i++) 
					{
					if (i == (pAdapter->AddressLength - 1))
						printf("%.2X\n", (int) pAdapter->Address[i]);
					else
						printf("%.2X-", (int) pAdapter->Address[i]);
					}            
				printf("\tAdapter Type: \t");
				switch (pAdapter->Type) 
					{
					case MIB_IF_TYPE_OTHER:		printf("Other\n"); break;
					case MIB_IF_TYPE_ETHERNET:	printf("Ethernet\n"); break;
					case MIB_IF_TYPE_TOKENRING:	printf("Token Ring\n"); break;
					case MIB_IF_TYPE_FDDI:		printf("FDDI\n"); break;
					case MIB_IF_TYPE_PPP:		printf("PPP\n"); break;
					case MIB_IF_TYPE_LOOPBACK:	printf("Lookback\n"); break;
					case MIB_IF_TYPE_SLIP:		printf("Slip\n"); break;
					default:	                printf("Unknown type %ld\n", pAdapter->Type); break;
					}

				printf("\tIP Address: \t%s\n", pAdapter->IpAddressList.IpAddress.String);
				printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);
				printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);

				if (pAdapter->DhcpEnabled) 
					{
					printf("\tDHCP Enabled: \tYes\n");
					printf("\tDHCP Server: \t%s\n\n", pAdapter->DhcpServer.IpAddress.String);
					} 
				else
					printf("\tDHCP Enabled: No\n\n");

				// Recopie adresse Mac
				for (i = 0 ; i < 6 ; i++) 
					{
					adr_eth->oct[i]= pAdapter->Address[i];
					}       
				 
				break;
				}
			else
				{
				pAdapter = pAdapter->Next;
				}
		   }
		} 
	else 
		{
        printf("GetAdaptersInfo() failed with error: %d\n", RetVal);
		return 4;
		}

	if (pAdapterInfo) Free(pAdapterInfo);

	return 0;		// OK
	}

// Recuperation de l'adresse IPv4 d'une interface Ethernet
// hp= Handle de l'interface ouverte
// adr_ip= structure qui recevra l'adresse
// Retourne 0 si OK

int Npkt_GetIpAddress(Npkt_Handle hp, struct ADR_ip * adr_ip)
	{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD RetVal = 0;
	ULONG ulOutBufLen= 0;
    UINT i;
	char * pos1, * pos2;
	char name[256]= "";
	unsigned numa, numb, numc, numd;

	* adr_ip= NUL_IP;
	if (hp == NULL) return 1;

	// Nom Windows de l'interface entre { }
	pos1= strchr(hp->ifhd->name, '{');
	pos2= strrchr(hp->ifhd->name, '}');
	if ((pos1 != NULL) && (pos2 != NULL))
		strncpy(name, pos1, (int) (pos2-pos1) +1);
	else 
		return 2;

    ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) Malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) 
		{
        printf("Error allocating memory for GetAdaptersinfo()\n");
        return 3;
		}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
		{
        Free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) Malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) 
			{
            printf("Error allocating memory for GetAdaptersinfo()\n");
            return 3;
			}
		}

    if ((RetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
		{
        pAdapter = pAdapterInfo;

        while (pAdapter) 
			{
			if ((strcmp(pAdapter->AdapterName, name) == 0) && (pAdapter->Type == MIB_IF_TYPE_ETHERNET))
				{
				// Recopie adresse Ip				
				sscanf(pAdapter->IpAddressList.IpAddress.String, "%u.%u.%u.%u", &numa, &numb, &numc, &numd);
				sprintf(adr_ip->dec, "%c%c%c%c", numa, numb, numc, numd);
				 
				break;
				}
			else
				{
				pAdapter = pAdapter->Next;
				}
		   }
		} 
	else 
		{
        printf("GetAdaptersInfo() failed with error: %d\n", RetVal);
		return 4;
		}

	if (pAdapterInfo) Free(pAdapterInfo);

	return 0;		// OK
	}


// Recuperation du masque IPv4 d'une interface Ethernet
// hp= Handle de l'interface ouverte
// adr_ip= structure qui recevra l'adresse
// Retourne 0 si OK

int Npkt_GetIpMask(Npkt_Handle hp, struct ADR_ip * msk_ip)
	{
    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD RetVal = 0;
	ULONG ulOutBufLen= 0;
    UINT i;
	char * pos1, * pos2;
	char name[256]= "";
	unsigned numa, numb, numc, numd;

	* msk_ip= NUL_IP;
	if (hp == NULL) return 1;

	// Nom Windows de l'interface entre { }
	pos1= strchr(hp->ifhd->name, '{');
	pos2= strrchr(hp->ifhd->name, '}');
	if ((pos1 != NULL) && (pos2 != NULL))
		strncpy(name, pos1, (int) (pos2-pos1) +1);
	else 
		return 2;

    ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) Malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) 
		{
        printf("Error allocating memory for GetAdaptersinfo()\n");
        return 3;
		}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
		{
        Free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) Malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) 
			{
            printf("Error allocating memory for GetAdaptersinfo()\n");
            return 3;
			}
		}

    if ((RetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
		{
        pAdapter = pAdapterInfo;

        while (pAdapter) 
			{
			if ((strcmp(pAdapter->AdapterName, name) == 0) && (pAdapter->Type == MIB_IF_TYPE_ETHERNET))
				{
				// Recopie adresse Ip				
				sscanf(pAdapter->IpAddressList.IpMask.String, "%u.%u.%u.%u", &numa, &numb, &numc, &numd);
				sprintf(msk_ip->dec, "%c%c%c%c", numa, numb, numc, numd);
				 
				break;
				}
			else
				{
				pAdapter = pAdapter->Next;
				}
		   }
		} 
	else 
		{
        printf("GetAdaptersInfo() failed with error: %d\n", RetVal);
		return 4;
		}

	if (pAdapterInfo) Free(pAdapterInfo);

	return 0;		// OK
	}

// Emission d'une trame brute sur le reseau
// hp= Handle de l'interface ouverte
// trame= adresse de la structure trame a envoyer
// flen= taille de la trame
// Retourne 0 si OK et -1 en cas d'erreur

int Npkt_Send(Npkt_Handle hp, struct TRAME_eth * trame, unsigned flen)
	{
	int i= 0;

	// Attention : il faut assurer le bourrage jusqu'à 60 octets si necessaire !!!
	if (flen < 60)
		{
		for (i= flen ; i < 60 ; i++)
			((u_char *) trame)[i]= 0;
		flen= 60;
		}

	return pcap_sendpacket(hp->pkthd, (u_char *) trame, flen);
	}

// reception d'une trame brute sur le reseau
// hp= Handle de l'interface ouverte
// trame= adresse de la structure trame a remplir
// type= type de trame (TYPE_ARP, TYPE_IP ou 0 pour tout)
// Retourne la taille de la trame recue ; 0 si RAS et < 0 en cas d'erreur

int Npkt_Receive(Npkt_Handle hp, struct TRAME_eth * trame, u_short type)
	{
	struct pcap_pkthdr * header;		// contient horodatage
	u_char *pkt_data;
	u_short t;
	int res= 0;

	while((res = pcap_next_ex(hp->pkthd, &header, &pkt_data) >= 0))
		{
		if (res == 0) return 0;		// RAS

		if (type != 0)
			{
			t= ((struct TRAME_eth *) pkt_data)->type;		// filtrage par type de trame
			if (xchg(t) != type) continue;
			}

		memcpy((u_char *) trame, pkt_data, header->caplen);	
		return header->caplen;
		}

	return res;		// Erreur si res < 0
	}

// Fermeture d'un handle ouvert
// hp= Handle de l'interface ouverte

void Npkt_Close(Npkt_Handle hp)
	{
	if (hp == NULL) return;

	printf("Closing interface\n\n");
	// Free interface list
	pcap_freealldevs(hp->devs);
	// Close packet driver access
	pcap_close(hp->pkthd);

	// Free allocated memory
	Free(hp);
	}

