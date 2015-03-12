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

type t =
  | ETH of Ethernet.h * t
  | VLAN of Ethernet.Vlan.h * t

  | IP4 of Ip4.h * t
  | TCP4 of Tcp4.h * t
  | UDP4 of Udp4.h * t

  | DHCP of Dhcp4.t
  | ARP of Arp.t

  | DATA of Cstruct.t
  | ERROR of Cstruct.t
  | DROP

let to_str pkt =
  let rec aux pkt str =
    match pkt with
    | ETH (h, p) ->
      let s = sprintf "%s|ETH(%s)" str (Ethernet.to_str h) in aux p s
    | VLAN (h, p) ->
      let s = sprintf "%s|VLAN(%s)" str (Ethernet.Vlan.to_str h) in aux p s

    | IP4 (h, p) ->
      let s = sprintf "%s|IP4(%s)" str (Ip4.to_str h) in aux p s
    | TCP4 (h, p) ->
      let s = sprintf "%s|TCP4(%s)" str (Tcp4.to_str h) in aux p s
    | UDP4 (h, p) ->
      let s = sprintf "%s|UDP4(%s)" str (Udp4.to_str h) in aux p s

    | DHCP p -> sprintf "%s|%s" str (Dhcp4.to_str p)
    | ARP p -> sprintf "%s|%s" str (Arp.to_str p)

    | DATA bs -> sprintf "%s|DATA(.)" str
    | ERROR bs -> sprintf "%s|ERR(%s)" str (Buf.to_string "\n\t" bs)
    | DROP -> sprintf "%s|." str
  in
  aux pkt ""

let to_string pkt =
  let rec aux pkt str =
    match pkt with
    | ETH (h, p) ->
      let s = sprintf "%s|ETH(%s)" str (Ethernet.to_string h) in aux p s
    | VLAN (h, p) ->
      let s = sprintf "%s|VLAN(%s)" str (Ethernet.Vlan.to_string h) in aux p s

    | IP4 (h, p) ->
      let s = sprintf "%s|IP4(%s)" str (Ip4.to_string h) in aux p s
    | TCP4 (h, p) ->
      let s = sprintf "%s|TCP4(%s)" str (Tcp4.to_string h) in aux p s
    | UDP4 (h, p) ->
      let s = sprintf "%s|UDP4(%s)" str (Udp4.to_string h) in aux p s

    | DHCP p -> sprintf "%s|%s" str (Dhcp4.to_string p)
    | ARP p -> sprintf "%s|%s" str (Arp.to_string p)

    | DATA bs -> sprintf "%s|DATA(%s)" str (Buf.to_string "\n\t" bs)
    | ERROR bs -> sprintf "%s|ERR(%s)" str (Buf.to_string "\n\t" bs)
    | DROP -> sprintf "%s|." str
  in
  aux pkt ""
