/*
 * Test NpCap afin de realiser une librairie de type Packet Driver
 * @(#) JG 2020
 * A compiler sous VC++
 *
 */

// NB: il n'est pas nécessaire de désactiver Unicode


#include "pcap.h"
#include "tcpip.h"

#include "NpktLib.h"



// Affichage brut d'une trame
void show_trame(char * trm_ptr, int siz)		
	{
	int i;
	unsigned char c;
	unsigned char * c_ptr;

	for (i= 0 ; i < siz ; i++)
		{
		c_ptr= (unsigned char *) trm_ptr;
		c= *(c_ptr+i);
		printf("%2.2X ", c);
		}

	printf("\n\n");
	}

// Conversion ordre normalise reseau
u_short xchg(u_short x)
	{
	u_short y= x >> 8;
	y+= x << 8;

	return y;
	}



int main()
	{





	getch();
	return 0;
	}
