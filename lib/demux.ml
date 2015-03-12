(*
 * Copyright (c) 2013 Richard Mortier <mort@cantab.net>
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

(** break the cycle: Packet depends on various formats (Ethernet, etc); but
    demux results in a Packet.t element, hence can't include demux functions
    in the format modules themselves. could put them in Packet but seems
    cleaner to break them out. *)

open Packet

(** stop_demuxf: buf -> Packet.t *)

let drop_demux _ = DROP

let data_demux buf = DATA buf

(** demuxf: 'st -> 'proto_demuxf -> buf -> Packet.t *)

let udp4_demux st port_demux buf =
  let open Udp4 in
  let uh = h buf in
  let buf = Cstruct.shift buf sizeof_udp4 in
  UDP4(uh, (port_demux st uh) buf)

let tcp4_demux st port_demux buf =
  let open Tcp4 in
  let th = h buf in
  let buf = Cstruct.shift buf sizeof_tcp4 in
  TCP4(th, (port_demux st th) buf)

let ip_demux st ipproto_demux buf =
  let open Ip4 in
  let ih = h buf in
  let buf = Cstruct.shift buf sizeof_ip4 in
  IP4(ih, (ipproto_demux st ih) buf)

let eth_demux st ethertype_demux buf =
  let open Ethernet in
  let eh = h buf in
  let buf = Cstruct.shift buf sizeof_ethernet in
  ETH(eh, (ethertype_demux st eh) buf)

let vlan_demux st ethertype_demux buf =
  let open Ethernet.Vlan in
  let vh = h buf in
  let buf = Cstruct.shift buf sizeof_vlan in
  VLAN(vh, (ethertype_demux st vh) buf)

(** proto_demuxf: 'st -> h -> demuxf *)

let udp4_port_demux st uh =
  let open Ip4 in
  match int_to_port uh.Udp4.dstpt with
  | None -> data_demux
  | Some p -> match p with
    | BOOTPS | BOOTPC
      -> (fun buf ->
          Dhcp4.(DHCP(h buf, UNKNOWN(Cstruct.shift buf sizeof_dhcp4))))
    | _ -> data_demux

let tcp4_port_demux st th =
  let open Ip4 in
  match int_to_port th.Tcp4.dstpt with
  | None -> data_demux
  | Some p -> match p with
    | _ -> data_demux

let ipproto_demux st ih =
  let open Ip4 in
  match int_to_protocol ih.proto with
  | None -> data_demux
  | Some t -> match t with
    | UDP -> udp4_demux st udp4_port_demux
    | TCP -> tcp4_demux st tcp4_port_demux
    | _ -> data_demux

let rec vlan_ethertype_demux st vh =
  let open Ethernet in
  match int_to_ethertype vh.Vlan.ethertype with
  | None -> data_demux
  | Some t -> match t with
    | IP4 -> ip_demux st ipproto_demux
    | VLAN -> vlan_demux st vlan_ethertype_demux (* ugly *)
    | _ -> data_demux

let ethertype_demux st eh =
  let open Ethernet in
  match int_to_ethertype eh.ethertype with
  | None -> data_demux
  | Some t -> match t with
    | IP4 -> ip_demux st ipproto_demux
    | VLAN -> vlan_demux st vlan_ethertype_demux (* ugly *)
    | _ -> data_demux
