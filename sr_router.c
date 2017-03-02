/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  uint16_t __ethertype = ethertype(packet);

  struct sr_if *receive_interface = sr_get_interface(sr, interface);

  switch(__ethertype) {
    case ethertype_arp:
      sr_handle_arp(sr, packet, len, receive_interface);
      break;
    case ethertype_ip:
      sr_handle_ip(sr, packet, len, receive_interface);
      break;
    default:
      fprintf(stderr, "Received Unknow Packet, dropping\n");
      return;
  }
}/* end sr_ForwardPacket */




/*=====================UTILS===============================*/
void sr_forward_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t* dst_mac, struct sr_if *out_interface) {

  sr_ethernet_hdr_t* eth_hdr = get_eth_header(packet);
  sr_ip_hdr_t* ip_hdr = get_ip_header(packet);

  /*set the destination mac and the source addr*/
  memcpy(eth_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

  /*recompute the checksum as many field changed*/
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum((const void *)ip_hdr, sizeof(sr_ip_hdr_t)); 

  sr_send_packet(sr, packet, len, out_interface->name);
}

void sr_do_forwarding(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *receive_interface) {

  sr_ip_hdr_t* ip_hdr = get_ip_header(packet);

  /*find the longest prefix match according to the protocol*/
  struct sr_if *forward_interface = find_longest_prefix_match(sr, ip_hdr->ip_dst);
  
  /*if we can find one, then forward it, else send net unreachable icmp*/
  if(forward_interface) {
    /*look up the mac in the cache*/
    struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    if(entry) {
      sr_forward_packet(sr, packet, len, entry->mac, forward_interface);
      free(entry);
    } else {
      /*if not in cache, put into the queue and send a arp request*/
      struct sr_arpreq *request = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, out_if->name);
      sr_arpcache_handle_req_sending(sr, request);
    }
  } else {
    printf(" No match, sending ICMP network unreachable back\n");
    sr_send_icmp_err(sr, packet, NET_UNREACHEABLE_TYPE, NET_UNREACHEABLE_CODE, receive_interface);
  }
  return;
}



int check_ip_packet(sr_ip_hdr_t *ip_hdr, unsigned int len) {

  uint16_t tmp_sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;

  int err = (len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) && cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == tmp_sum);

  ip_hdr->ip_sum = tmp_sum;

  return err;
}

int check_icmp_packet(sr_ip_hdr_t *ip_hdr, sr_icmp_hdr_t *icmp_hdr, unsigned int len) {

  uint16_t tmp_sum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;

  int err = (len >= (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) && cksum(ip_hdr, sizeof(sr_ip_hdr_t)) == tmp_sum);

  icmp_hdr->icmp_sum = tmp_sum;

  return err;
}


struct sr_if* find_longest_prefix_match(struct sr_instance *sr, uint32_t __dst) {
  struct sr_rt* routing_table_itr = sr->routing_table;
  while(routing_table_itr) {
    /*mask the __dst to make it same length as the ip with the tabke*/
    uint32_t dist = routing_table_itr->mask.s_addr & __dst;
    /*if same, return the interface*/
    if(dist == routing_table_itr->dest.s_addr)
       return sr_get_interface(sr, routing_table_itr->interface);
    routing_table_itr = routing_table_itr->next;
  }
  return NULL;
}

/*=====================ARP===============================*/

void sr_handle_arp(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *receive_interface) {

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  fprintf(stderr, "ARP\n");

  switch(ntohs(arp_hdr->ar_op)) {
    case arp_op_request:
      sr_handle_arp_request(sr, eth_hdr, arp_hdr, receive_interface);
      break;
    case arp_op_reply:
      sr_handle_arp_reply(sr, arp_hdr, receive_interface);
      break;
    default:
      return;
  }
}


void sr_handle_arp_request(struct sr_instance* sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* receive_interface) {
  //cache the arp of the sender
  pthread_mutex_lock(&sr->cache.lock);
  sr_arpcache_insert(&sr->cache, req_arp_hdr->ar_sha, req_arp_hdr->ar_sip);
  pthread_mutex_unlock(&sr->cache.lock);

  sr_send_arp_reply(sr, req_eth_hdr, req_arp_hdr, receive_interface);

}


int sr_send_arp_reply(struct sr_instance *sr, sr_ethernet_hdr_t *req_eth_hdr, sr_arp_hdr_t *req_arp_hdr, struct sr_if* receive_interface) {
  
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *rep_packet = (uint8_t *)malloc(len);
  memset(rep_packet, 0, len);

  sr_ethernet_hdr_t* rep_eth_hdr = get_eth_header(rep_packet);
  sr_arp_hdr_t* rep_arp_hdr = get_arp_header(rep_packet);

  memcpy(rep_eth_hdr->ether_dhost, req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(rep_eth_hdr->ether_shost, receive_interface->addr, ETHER_ADDR_LEN);
  rep_eth_hdr->ether_type = ntohs(ethertype_arp);

  rep_arp_hdr->ar_hrd = req_arp_hdr->ar_hrd;
  rep_arp_hdr->ar_pro = req_arp_hdr->ar_pro;
  rep_arp_hdr->ar_hln = req_arp_hdr->ar_hln;
  rep_arp_hdr->ar_pln = req_arp_hdr->ar_pln;
  rep_arp_hdr->ar_op = htons(arp_op_reply);
  rep_arp_hdr->ar_sip = receive_interface->ip;
  rep_arp_hdr->ar_tip = req_arp_hdr->ar_sip;
  memcpy(rep_arp_hdr->ar_sha, receive_interface->addr, ETHER_ADDR_LEN);
  memcpy(rep_arp_hdr->ar_tha, req_arp_hdr->ar_sha, ETHER_ADDR_LEN);

  int err = sr_send_packet(sr, rep_packet, len, receive_interface->name);
  /*free(rep_packet)*/
  return err;
}


void sr_handle_arp_reply(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if* receive_interface) {

  if(arp_hdr->ar_tip == receive_interface->ip) {
  
    pthread_mutex_lock(&sr->cache.lock);
    /*insert the reply to our cache*/
    struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    /*if there are packets in the queue*/
    if(request) {

      struct sr_packet *waiting_packet_itr = request->packets;

      while(waiting_packet_itr) {
        /*send it*/
        sr_forward_packet(sr, waiting_packet_itr->buf, waiting_packet_itr->len, arp_hdr->ar_sha, receive_interface);
        waiting_packet_itr = waiting_packet_itr->next; 
      }
      sr_arpreq_destroy(&sr->cache, request);
    }
    pthread_mutex_unlock(&sr->cache.lock);
  }
}





/*=====================IP===============================*/
void sr_handle_ip(struct sr_instance* sr, uint8_t *packet, unsigned int len, struct sr_if *receive_interface) {
  
  sr_ip_hdr_t *ip_hdr = get_ip_header(packet);

  /*checksum and the length according to the protocol*/
  if(!check_ip_packet(ip_hdr, len)) return;

  struct sr_if *interface_itr = sr->if_list;
  /*Test whether this ip packet is for me*/
  while(interface_itr) {
    if(interface_itr->ip == ip_hdr->ip_dst) {
      sr_handle_ip_rec(sr, packet, len, interface_itr);
      return;
    }
    interface_itr = interface_itr->next;
  }

  /*not for me*/
  ip_hdr->ip_ttl--;

  if(ip_hdr->ip_ttl == 0) {
    printf("TTL is 0, sending ICMP time exceeded\n");
    sr_send_icmp_err(sr, packet, TIME_EXCEEDED_TYPE, TIME_EXCEEDED_CODE, receive_interface);
    return;
  }
  sr_do_forwarding(sr, packet, len, receive_interface);
}



void sr_handle_ip_rec(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *receive_interface) {

  sr_ip_hdr_t *ip_hdr = get_ip_header(packet);

  if(ip_protocol_icmp == ip_hdr->ip_p) {
    sr_icmp_ping_hdr_t *icmp_hdr = get_icmp_header(packet);

    if(!check_icmp_packet(ip_hdr, icmp_hdr, len)) return;

    if(icmp_hdr->icmp_type == ECHO_REQUEST_TYPE) {
      sr_send_icmp_ping(sr, ECHO_REPLY_TYPE, ECHO_REPLY_CODE, packet, len, receive_interface);
    }
  }else {
    /*a TCP/UDP with payload is sent to one of the router's interfaces. This is needed for traceroute to work*/
    sr_send_icmp_err(sr, packet, PORT_UNREACHEABLE_TYPE, PORT_UNREACHEABLE_CODE, receive_interface);
  }
}



/*=====================ICMP===============================*/
int sr_send_icmp_ping(struct sr_instance *sr, uint8_t icmp_type, uint8_t icmp_code, uint8_t *packet, int len, struct sr_if * receive_interface) {
  
  sr_ethernet_hdr_t *eth_hdr = get_eth_header(packet);
  sr_ip_hdr_t *ip_hdr = get_ip_header(packet);
  sr_icmp_t11_hdr_t *icmp_hdr = get_icmp_header(packet);

  struct sr_if *out_interface = find_longest_prefix_match(sr, ip_hdr->ip_src);

  /*the shost become dhost, and our interface is the source*/
  memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

  /*swap the ip*/
  uint32_t req_src = ip_hdr->ip_src;
  ip_hdr->ip_src = receive_interface->ip;
  ip_hdr->ip_dst = req_src;

  /*prepare the icmp_header*/
  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_ping_hdr_t)); 

  int err = sr_send_packet(sr, packet, len, out_interface->name);
  return err;
}

int sr_send_icmp_err(struct sr_instance *sr, uint8_t *receiver, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *receive_interface) {

  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
  
  uint8_t *packet = (uint8_t *)malloc(len);
  memset(packet, 0, len);

  sr_ethernet_hdr_t *eth_hdr = get_eth_header(packet);
  sr_ip_hdr_t *ip_hdr = get_ip_header(packet);
  sr_icmp_t11_hdr_t *icmp_hdr = get_icmp_header(packet);

  sr_ethernet_hdr_t *rec_eth_hdr = get_eth_header(receiver);
  sr_ip_hdr_t *rec_ip_hdr = get_ip_header(receiver);

  struct sr_if *out_interface = find_longest_prefix_match(sr, rec_ip_hdr->ip_src);

  memcpy(eth_hdr->ether_dhost, rec_eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);

  ip_hdr->ip_hl = rec_ip_hdr->ip_hl;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_tos = rec_ip_hdr->ip_tos;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_v = rec_ip_hdr->ip_v;
  ip_hdr->ip_src = receive_interface->ip;
  ip_hdr->ip_dst = rec_ip_hdr->ip_src;
  ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  icmp_hdr->icmp_type = icmp_type;
  icmp_hdr->icmp_code = icmp_code;
  memcpy(icmp_hdr->data, rec_ip_hdr, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));

  int err = sr_send_packet(sr, packet, len, out_interface->name);
  return err;
}


