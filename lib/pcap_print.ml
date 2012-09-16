(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Pcap

cstruct ethernet {
  uint8_t        dst[6];
  uint8_t        src[6];
  uint16_t       ethertype
} as big_endian

cstruct ipv4 {
  uint8_t        hlen_version;
  uint8_t        tos;
  uint16_t       len;
  uint16_t       id;
  uint16_t       off;
  uint8_t        ttl;
  uint8_t        proto;
  uint16_t       csum;
  uint8_t        src[4];
  uint8_t        dst[4]
} as big_endian

cstruct tcpv4 {
  uint16_t       src_port;
  uint16_t       dst_port;
  uint32_t       seqnum;
  uint32_t       acknum;
  uint16_t       offset_flags;
  uint16_t       window;
  uint16_t       checksum;
  uint16_t       urg
} as big_endian

open Printf

let mac_to_string buf =
  let i n = Cstruct.get_uint8 buf n in
  sprintf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
    (i 0) (i 1) (i 2) (i 3) (i 4) (i 5)

let print_packet p =
  let dst_mac = mac_to_string (get_ethernet_dst p) in
  let src_mac = mac_to_string (get_ethernet_src p) in
  let ethertype = get_ethernet_ethertype p in
  printf "ether %s -> %s etype %x\n" src_mac dst_mac ethertype;
  match ethertype with
  |0x0800 -> begin
     let ip = Cstruct.shift p sizeof_ethernet in
     let version = get_ipv4_hlen_version ip lsr 4 in
     let hlen = (get_ipv4_hlen_version ip land 0xf) * 4 in
     let ttl = get_ipv4_ttl ip in
     let proto = get_ipv4_proto ip in
     printf "ipv%d hlen %d ttl %d proto %d\n" version hlen ttl proto;
     match proto with 
     |6 -> begin (* tcp *)
       let tcp = Cstruct.shift ip sizeof_ipv4 in
       let off = 0 in
       let x = get_tcpv4_offset_flags tcp in
       let data_offset = (x lsr 12) * 4 in
       let options =
         match data_offset - sizeof_tcpv4 with
         |0 -> 0
         |n -> n (* TODO parse *)
       in
       let payload = Cstruct.shift tcp data_offset in
       let fin = (x land 1) = 1 in
       let syn = (x land 2) = 2 in
       let flags = "?" in
       printf "tcpv4 port %d->%d seq %lu ack %lu win %d off %d flags %s opt %d fin %b syn %b\n"
         (get_tcpv4_src_port tcp) (get_tcpv4_dst_port tcp) (get_tcpv4_seqnum tcp)
         (get_tcpv4_acknum tcp) (get_tcpv4_window tcp) off flags options fin syn;
       printf "%S\n" (Cstruct.to_string payload)
     end
     |_ -> printf "unknown ip proto %d\n" proto
  end
  |_ -> printf "unknown body\n"
 
let rec print_pcap_packet h (hdr,pkt) =
  let module H = (val h: HDR) in
  let open H in
  printf "\n** %lu.%lu  bytes %lu (of %lu)\n" 
    (get_pcap_packet_ts_sec hdr)
    (get_pcap_packet_ts_usec hdr)
    (get_pcap_packet_incl_len hdr)
    (get_pcap_packet_orig_len hdr);
  print_packet pkt
  
let print_pcap_header h buf =
  let module H = (val h: HDR) in
  let open H in
  printf "pcap_header (len %d)\n" sizeof_pcap_header;
  printf "endian: %s\n" (string_of_endian H.endian);
  printf "version %d %d\n" 
   (get_pcap_header_version_major buf) (get_pcap_header_version_minor buf);
  printf "timezone shift %lu\n" (get_pcap_header_thiszone buf);
  printf "timestamp accuracy %lu\n" (get_pcap_header_sigfigs buf);
  printf "snaplen %lu\n" (get_pcap_header_snaplen buf);
  printf "lltype %lx\n" (get_pcap_header_network buf)



