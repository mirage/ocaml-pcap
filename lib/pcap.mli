(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (C) 2012 Citrix Systems Inc
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

val major_version: int
(** Major version of the pcap format which we understand *)

val minor_version: int
(** Minor version of the pcap format which we understand *)

type endian =
| Big     (** Big endian (pcap headers) *)
| Little  (** Little endian (pcap headers) *)

val string_of_endian : endian -> string

val sizeof_pcap_header: int
(** The size of the initial pcap header in bytes *)

val sizeof_pcap_packet: int
(** The size of the per-packet pcap headers in bytes *)

val magic_number: int32
(** The magic number which identifies a pcap file (and endian-ness) *)

module Network : sig
  (** Type of outermost network protocol within the captured frames *)

  type t =
    | Ethernet
    | Ieee80211

  val to_int32: t -> int32

  val of_int32: int32 -> t option

end

module LE : sig

  val endian : endian

  cstruct pcap_header {
    uint32_t magic_number;   (* magic number *)
    uint16_t version_major;  (* major version number *)
    uint16_t version_minor;  (* minor version number *)
    uint32_t thiszone;       (* GMT to local correction *)
    uint32_t sigfigs;        (* accuracy of timestamps *)
    uint32_t snaplen;        (* max length of captured packets, in octets *)
    uint32_t network         (* data link type *)
  } as little_endian

  cstruct pcap_packet {
    uint32_t ts_sec;         (* timestamp seconds *)
    uint32_t ts_usec;        (* timestamp microseconds *)
    uint32_t incl_len;       (* number of octets of packet saved in file *)
    uint32_t orig_len        (* actual length of packet *)
  } as little_endian

end

module BE : sig

  val endian : endian

  cstruct pcap_header {
    uint32_t magic_number;   (* magic number *)
    uint16_t version_major;  (* major version number *)
    uint16_t version_minor;  (* minor version number *)
    uint32_t thiszone;       (* GMT to local correction *)
    uint32_t sigfigs;        (* accuracy of timestamps *)
    uint32_t snaplen;        (* max length of captured packets, in octets *)
    uint32_t network         (* data link type *)
  } as big_endian

  cstruct pcap_packet {
    uint32_t ts_sec;         (* timestamp seconds *)
    uint32_t ts_usec;        (* timestamp microseconds *)
    uint32_t incl_len;       (* number of octets of packet saved in file *)
    uint32_t orig_len        (* actual length of packet *)
  } as big_endian

end

module type HDR = sig
  (** Functions to read/write pcap header fields of a particular
      endian-ness *)

  val endian: endian
  (** The detected endian-ness of the headers *)

  val get_pcap_header_magic_number: Cstruct.buf -> int32
  val get_pcap_header_version_major: Cstruct.buf -> int
  val get_pcap_header_version_minor: Cstruct.buf -> int
  val get_pcap_header_thiszone: Cstruct.buf -> int32
  val get_pcap_header_sigfigs: Cstruct.buf -> int32
  val get_pcap_header_snaplen: Cstruct.buf -> int32
  val get_pcap_header_network: Cstruct.buf -> int32

  val set_pcap_header_magic_number: Cstruct.buf -> int32 -> unit
  val set_pcap_header_version_major: Cstruct.buf -> int -> unit
  val set_pcap_header_version_minor: Cstruct.buf -> int -> unit
  val set_pcap_header_thiszone: Cstruct.buf -> int32 -> unit
  val set_pcap_header_sigfigs: Cstruct.buf -> int32 -> unit
  val set_pcap_header_snaplen: Cstruct.buf -> int32 -> unit
  val set_pcap_header_network: Cstruct.buf -> int32 -> unit

  val get_pcap_packet_ts_sec: Cstruct.buf -> int32
  val get_pcap_packet_ts_usec: Cstruct.buf -> int32
  val get_pcap_packet_incl_len: Cstruct.buf -> int32
  val get_pcap_packet_orig_len: Cstruct.buf -> int32

  val set_pcap_packet_ts_sec: Cstruct.buf -> int32 -> unit
  val set_pcap_packet_ts_usec: Cstruct.buf -> int32 -> unit
  val set_pcap_packet_incl_len: Cstruct.buf -> int32 -> unit
  val set_pcap_packet_orig_len: Cstruct.buf -> int32 -> unit

end

val detect: Cstruct.buf -> (module HDR) option
(** [detect buf] returns a module capable of reading the pcap header fields, or
    None if the buffer doesn't contain pcap data. *)

val packets: (module HDR) -> Cstruct.buf -> (Cstruct.buf * Cstruct.buf) Cstruct.iter
(** [packets hdr buf] returns a Cstruct.iter (sequence) containing
    (pcap header, pcap body) pairs. *)
