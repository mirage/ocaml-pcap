(*
 * Copyright (C) 2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (C) 2012 Citrix Systems Inc
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

(** A sequence of packets serialised on disk in PCAP 2.x format.

    A container for a particular format of capture: somewhat like protocol
    dissectors that can't nest into a {! Packet.t}. Provides file-header [fh],
    element-header [h] and a tagged type [t]. For error reporting purposes, the
    type [t] will typically be something like [TAG of ( h * Packet.t * Cstruct.t
    )].
*)

(** Major version of the pcap format which we understand *)
val major_version: int

(** Minor version of the pcap format which we understand *)
val minor_version: int

(** Endianness of the capture file. *)
type endian =
  | Big
  | Little

val string_of_endian : endian -> string
val endian_to_string : endian -> string

(** The size of the initial pcap header in bytes *)
val sizeof_pcap_header: int

(** The size of the per-packet pcap headers in bytes *)
val sizeof_pcap_packet: int

val magic_number: int32
(** The magic number which identifies a pcap file (and endian-ness) *)

(** Type of outermost network protocol within the captured frames *)
module Network : sig

  type t =
    | Ethernet
    | Ieee80211

  val to_int32: t -> int32

  val of_int32: int32 -> t option

end

(** Little-endian version of PCAP file and packet headers. *)
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
    uint32_t caplen;         (* number of octets of packet saved in file *)
    uint32_t len             (* actual length of packet *)
  } as little_endian

end

(** Big-endian version of PCAP file and packet headers. *)
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
    uint32_t caplen;         (* number of octets of packet saved in file *)
    uint32_t len             (* actual length of packet *)
  } as big_endian

end

(** Functions to read/write pcap header fields of a particular endian-ness. *)
module type HDR = sig

  (** The detected endian-ness of the headers *)
  val endian: endian

  val get_pcap_header_magic_number: Cstruct.t -> int32
  val get_pcap_header_version_major: Cstruct.t -> int
  val get_pcap_header_version_minor: Cstruct.t -> int
  val get_pcap_header_thiszone: Cstruct.t -> int32
  val get_pcap_header_sigfigs: Cstruct.t -> int32
  val get_pcap_header_snaplen: Cstruct.t -> int32
  val get_pcap_header_network: Cstruct.t -> int32

  val set_pcap_header_magic_number: Cstruct.t -> int32 -> unit
  val set_pcap_header_version_major: Cstruct.t -> int -> unit
  val set_pcap_header_version_minor: Cstruct.t -> int -> unit
  val set_pcap_header_thiszone: Cstruct.t -> int32 -> unit
  val set_pcap_header_sigfigs: Cstruct.t -> int32 -> unit
  val set_pcap_header_snaplen: Cstruct.t -> int32 -> unit
  val set_pcap_header_network: Cstruct.t -> int32 -> unit

  val get_pcap_packet_ts_sec: Cstruct.t -> int32
  val get_pcap_packet_ts_usec: Cstruct.t -> int32
  val get_pcap_packet_caplen: Cstruct.t -> int32
  val get_pcap_packet_len: Cstruct.t -> int32

  val set_pcap_packet_ts_sec: Cstruct.t -> int32 -> unit
  val set_pcap_packet_ts_usec: Cstruct.t -> int32 -> unit
  val set_pcap_packet_caplen: Cstruct.t -> int32 -> unit
  val set_pcap_packet_len: Cstruct.t -> int32 -> unit

end

(** Parsed PCAP file header. *)
type fh = {
  magic_number: int32;          (** For endianness detection *)
  endian: endian;               (** Endianness of capture  *)
  version_major: int;           (** Major version *)
  version_minor: int;           (** Minor version *)
  timezone: int32;              (** GMT to local correction *)
  sigfigs: int32;               (** Accuracy of timestamps *)
  snaplen: int32;               (** Max length of captured packets, in octets *)
  network: int32                (** Data link type *)
}

(** Compact [fh] pretty-printer. *)
val fh_to_str: fh -> string

(** Verbose [fh] pretty-printer. *)
val fh_to_string: fh -> string

(** Parsed PCAP packet header. *)
type h = {
  secs: int32;
  usecs: int32;
  caplen: int;
  len: int;
}

(** Compact [h] pretty-printer. *)
val to_str: h -> string

(** Verbose [h] pretty-printer. *)
val to_string: h -> string

(** A captured PCAP packet: a header {! h}, the packet {! Packet.t} and the raw
    bytes {! Cstruct.t} for error reporting. *)
type t = PCAP of h * Packet.t * Cstruct.t

val iter: Cstruct.t -> (Cstruct.t -> Packet.t) -> (fh * t Cstruct.iter) option

val to_pkt: t -> Ocap.t
