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

open Printf

type bytes = Cstruct.t

[%%cenum
type op =
  | REQUEST  [@id 1]
  | RESPONSE [@id 2]
[@@uint8_t]]

[%%cenum
type hw =
  | ETHERNET  [@id 1]
  | HW_802_11 [@id 6] (* XXX spurious leading HW_ required by cstruct syntax *)
  | ARCNET    [@id 7]
[@@uint16_t]]

[%%cstruct
type arp = {
  hw:     uint16_t;
  pro:    uint16_t;
  hlen:   uint8_t;
  plen:   uint8_t;
  op:     uint16_t;
  shaddr: uint8_t  [@len 6];
  spaddr: uint32_t;
  dhaddr: uint8_t  [@len 6];
  dpaddr: uint32_t;
} [@@big_endian]]

type h = {
  hw: int;
  pro: int;
  hlen: int;
  plen: int;
  op: int;
  shaddr: bytes;
  spaddr: int32;
  dhaddr: bytes;
  dpaddr: int32;
}

let h buf =
  { hw = get_arp_hw buf;
    pro = get_arp_pro buf;
    hlen = get_arp_hlen buf;
    plen = get_arp_plen buf;
    op = get_arp_op buf;
    shaddr = get_arp_shaddr buf;
    spaddr = get_arp_spaddr buf;
    dhaddr = get_arp_dhaddr buf;
    dpaddr = get_arp_dpaddr buf;
  }

let h_to_str h =
  sprintf ""

let h_to_string h =
  let hw = match int_to_hw h.hw with
    | None -> sprintf "#%d" h.hw
    | Some v -> hw_to_string v
  in
  let op = match int_to_op h.op with
    | None -> sprintf "#%d" h.op
    | Some v -> op_to_string v
  in
  sprintf "hw:%s pro:%d hlen:%d plen:%d op:%s \
           shaddr:%s spaddr:%s dhaddr:%s dpaddr:%s"
    hw h.pro h.hlen h.plen op
    (Ethernet.mac_to_string h.shaddr) (Ip4.ip_to_string h.spaddr)
    (Ethernet.mac_to_string h.dhaddr) (Ip4.ip_to_string h.dpaddr)

type p = UNKNOWN of Cstruct.t
type t = h * p

let to_str (h, UNKNOWN p) = sprintf "ARP(%s)" (h_to_str h)
let to_string (h, UNKNOWN p) =
  sprintf "ARP(%s)|%s" (h_to_string h) (Buf.to_string "\n\t" p)
