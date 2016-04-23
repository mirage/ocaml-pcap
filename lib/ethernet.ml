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
open Cstruct

type bytes = Cstruct.t

[%%cenum
type ethertype =
  | IP4  [@id 0x0800]
  | ARP  [@id 0x0806]
  | IPX  [@id 0x8137]
  | VLAN [@id 0x8100]
  | IP6  [@id 0x86dd]
[@@uint16_t]]

[%%cstruct
type ethernet = {
  dst: uint8_t [@len 6];
  src: uint8_t [@len 6];
  ethertype: uint16_t;
} [@@big_endian]]

type h = {
  dst: bytes;
  src: bytes;
  ethertype: uint16;
}

let h buf =
  { dst = get_ethernet_dst buf;
    src = get_ethernet_src buf;
    ethertype = get_ethernet_ethertype buf;
  }

let mac_to_string mac =
  let i n = get_uint8 mac n in
  sprintf "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x"
    (i 0) (i 1) (i 2) (i 3) (i 4) (i 5)

let to_str h =
  let ethertype = match int_to_ethertype h.ethertype with
    | None -> sprintf "#%d" h.ethertype
    | Some e -> ethertype_to_string e
  in
  sprintf "%s,%s,%s" (mac_to_string h.src) (mac_to_string h.dst) ethertype

let to_string h =
  let ethertype = match int_to_ethertype h.ethertype with
    | None -> "###"
    | Some e -> ethertype_to_string e
  in
  sprintf "src:%s dst:%s type:%s"
    (mac_to_string h.src) (mac_to_string h.dst) ethertype

module Vlan = struct
  [%%cstruct
  type vlan = {
      tci: uint16_t;
      ethertype: uint16_t;
  } [@@big_endian]]

  type h = {
    tci: uint16;
    ethertype: uint16;
  }

  let h buf = {
    tci = get_vlan_tci buf;
    ethertype = get_vlan_ethertype buf;
  }

  let to_str h =
    let ethertype = match int_to_ethertype h.ethertype with
      | None -> sprintf "#%d" h.ethertype
      | Some e -> ethertype_to_string e
    in
    sprintf "%04x,%s" h.tci ethertype

  let to_string h =
    let ethertype = match int_to_ethertype h.ethertype with
      | None -> sprintf "#%d" h.ethertype
      | Some e -> ethertype_to_string e
    in
    sprintf "tci:%04x ethertype:%s" h.tci ethertype
end
