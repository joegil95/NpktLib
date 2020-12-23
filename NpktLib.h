/*
 * Librairie de type "Packet Driver" NpktLib basée sur Npcap (Windows x86 & x64)
 * A compiler sous VC++
 * @(#) JG 2020
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <conio.h>
#include <stddef.h>
#include <string.h>
#include <tchar.h>

#include <winsock2.h>

#include <iphlpapi.h>

#include "pcap.h"

typedef struct
	{
	pcap_t * pkthd;			// acces packet driver
	pcap_if_t * ifhd;		// interface associee
	pcap_if_t * devs;		// liste de toutes les interfaces
	}
Npkt_Struct;

typedef Npkt_Struct * Npkt_Handle;


// Ouverture d'un packet driver sur une interface reseau
Npkt_Handle Npkt_Open(int num, u_long flag);

// Recuperation de l'adresse Mac d'une interface Ethernet
int Npkt_GetMacAddress(Npkt_Handle hp, struct ADR_eth * adr_eth);

// Recuperation de l'adresse IPv4 d'une interface Ethernet
int Npkt_GetIpAddress(Npkt_Handle hp, struct ADR_ip * adr_ip);

// Recuperation du masque IPv4 d'une interface Ethernet
int Npkt_GetIpMask(Npkt_Handle hp, struct ADR_ip * msk_ip);

// Emission d'une trame brute sur le reseau
int Npkt_Send(Npkt_Handle hp, struct TRAME_eth * trame, unsigned flen);

// reception d'une trame brute sur le reseau
int Npkt_Receive(Npkt_Handle hp, struct TRAME_eth * trame, u_short type);

// Fermeture d'un handle ouvert
void Npkt_Close(Npkt_Handle hp);


#define Malloc(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define Free(x) HeapFree(GetProcessHeap(), 0, (x))


u_short xchg(u_short x);