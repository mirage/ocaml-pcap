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

cstruct dhcp4 {
  uint8_t  op;
  uint8_t  htype;
  uint8_t  hlen;
  uint8_t  hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;

  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;

  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128]
} as big_endian

type h = {
  op: int;
  htype: int;
  hlen: int;
  hops: int;
  xid: int32;
  secs: int;
  flags: int;

  ciaddr: int32;
  yiaddr: int32;
  siaddr: int32;
  giaddr: int32;

  chaddr: Cstruct.t;
  sname: Cstruct.t;
  file: Cstruct.t;
}

let h buf = {
  op = get_dhcp4_op buf;
  htype = get_dhcp4_htype buf;
  hops = get_dhcp4_hops buf;
  hlen = get_dhcp4_hlen buf;
  xid = get_dhcp4_xid buf;
  secs = get_dhcp4_secs buf;
  flags = get_dhcp4_flags buf;

  ciaddr = get_dhcp4_ciaddr buf;
  yiaddr = get_dhcp4_yiaddr buf;
  siaddr = get_dhcp4_siaddr buf;
  giaddr = get_dhcp4_giaddr buf;

  chaddr = get_dhcp4_chaddr buf;
  sname = get_dhcp4_sname buf;
  file = get_dhcp4_file buf;
}

let flags_to_string f =
  let is_bcast f = f land 0x8000 <> 0 in
  sprintf "%s" (if is_bcast f then "B" else ".")

let h_to_str h =
  sprintf "%d,%d,%d,%d, %08lx,%u,%s, %s,%s,%s,%s, '%s'"
    h.op h.htype h.hlen h.hops h.xid h.secs (flags_to_string h.flags)
    (Ip4.ip_to_string h.ciaddr) (Ip4.ip_to_string h.yiaddr)
    (Ip4.ip_to_string h.siaddr) (Ip4.ip_to_string h.giaddr)
    (Ethernet.mac_to_string h.chaddr)

let h_to_string h =
  sprintf "op:%d htype:%d hlen:%d hops:%d xid:%08lx secs:%d flags:%s \
           ciaddr:%s yiaddr:%s siaddr:%s giaddr:%s \
           chaddr:%s sname:'%s' file:'%s'"
    h.op h.htype h.hlen h.hops h.xid h.secs (flags_to_string h.flags)
    (Ip4.ip_to_string h.ciaddr) (Ip4.ip_to_string h.yiaddr)
    (Ip4.ip_to_string h.siaddr) (Ip4.ip_to_string h.giaddr)
    (Ethernet.mac_to_string h.chaddr)
    (Buf.to_string " " h.sname)
    (Buf.to_string " " h.file)

type p = UNKNOWN of Cstruct.t
type t = h * p

let to_str (h, UNKNOWN p) = sprintf "DHCP(%s)" (h_to_str h)
let to_string (h, UNKNOWN p) =
  sprintf "DHCP(%s)|%s" (h_to_string h) (Buf.to_string "\n\t" p)
