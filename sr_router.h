/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define get_eth_header(p) (sr_ethernet_hdr_t*)(p);
#define get_ip_header(p) (sr_ip_hdr_t *)(p + sizeof(sr_ethernet_hdr_t));
#define get_arp_header(p) (sr_arp_hdr_t*)(p + sizeof(sr_ethernet_hdr_t));
#define get_icmp_header(p) (sr_icmp_ping_hdr_t*)(p+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );


/* -- tmp here -- */
#define NET_UNREACHEABLE_TYPE 0x3
#define HOST_UNREACHEABLE_TYPE 0x3
#define PORT_UNREACHEABLE_TYPE 0x3
#define ECHO_REPLY_TYPE 0x0
#define ECHO_REQUEST_TYPE 0x8
#define TIME_EXCEEDED_TYPE 0xB


#define NET_UNREACHEABLE_CODE 0x0
#define HOST_UNREACHEABLE_CODE 0x1
#define PORT_UNREACHEABLE_CODE 0x3
#define ECHO_REPLY_CODE 0x0
#define ECHO_REQUEST_CODE 0x0
#define TIME_EXCEEDED_CODE 0x0

void sr_handle_arp(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *receive_interface);
void sr_handle_arp_request(struct sr_instance* sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* receive_interface);
int sr_send_arp_rep(struct sr_instance *sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* receive_interface);
void sr_handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if* receive_interface);
void sr_forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* dest_mac, struct sr_if *out_iface);
void sr_handle_ip(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *receive_interface);
int check_ip_packet(sr_ip_hdr_t *ip_hdr, unsigned int len);
void sr_do_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);
struct sr_if* find_longest_prefix_match(struct sr_instance *sr, uint32_t __dst);
int sr_send_icmp_err(struct sr_instance *sr, uint8_t *receiver, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *rec_iface);
int sr_send_arp_req(struct sr_instance *sr, uint32_t tip);
void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *rec_iface);
int sr_send_icmp_ping(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, int len, struct sr_if * rec_iface);





#endif /* SR_ROUTER_H */
