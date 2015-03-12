(*
 * Copyright (C) 2013 Richard Mortier <mort@cantab.net>
 *                    Richard Clegg <richard@richardclegg.org>
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

(** Basic, concrete packet abstraction.

    A container for all the various protocol dissectors. Provides a {! Packet.t}
    representing a captured packet as a recursive type to support tunnelling.
    Maps to a tagged union plus a couple of helper functions in C.

    Elements of this type are tagged tuples provided by protocol dissectors,
    containing:
    + some opaque bytes, [Cstruct.t];
    + or a protocol-specific singleton (e.g., [Dhcp4.t]);
    + or a (header, packet) pair where the protocol permits layering (e.g.,
    [ Tcp4.h * Packet.t ]).
*)

(** Recursive type representing a captured packet. *)
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

(** Compact pretty printer for {! Packet.t}. *)
val to_str: t -> string

(** Verbose pretty printer for {! Packet.t}. *)
val to_string: t -> string
