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

let major_version = 2

let minor_version = 4

type endian = | Big | Little

let string_of_endian = function
| Big    -> "big"
| Little -> "little"

(* The pcap format allows the writer to use either big- or little- endian,
   depending on which is most convenient (higher performance). We are able
   to read both, but we haven't optimised the low-level set_* functions
   enough to make it worthwhile to bother detecting native endian-ness and
   switching. *)

module Network = struct

  type t =
    | Ethernet
    | Ieee80211

  let t_to_int32 = [
      Ethernet,  1l
    ; Ieee80211, 105l
  ]

  let int32_to_t = List.map (fun (x, y) -> y, x) t_to_int32

  let to_int32 x = List.assoc x t_to_int32

  let of_int32 x =
    if List.mem_assoc x int32_to_t
    then Some (List.assoc x int32_to_t)
    else None

end


module LE = struct
  let endian = Little

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

module BE = struct
  let endian = Big

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

let sizeof_pcap_header = BE.sizeof_pcap_header (* = LE.sizeof_pcap_header *)

let sizeof_pcap_packet = BE.sizeof_pcap_packet (* = LE.sizeof_pcap_packet *)

module type HDR = sig
  val endian: endian

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

let magic_number = 0xa1b2c3d4l

let detect buf =
  let le_magic = LE.get_pcap_header_magic_number buf in
  let be_magic = BE.get_pcap_header_magic_number buf in
  if le_magic = magic_number then Some (module LE: HDR)
  else if be_magic = magic_number then Some (module BE: HDR)
  else None

let packets h =
  let module H = (val h : HDR) in
  Cstruct.iter 
    (fun buf -> Some (sizeof_pcap_packet + (Int32.to_int (H.get_pcap_packet_incl_len buf))))
    (fun buf -> buf, (Cstruct.shift buf sizeof_pcap_packet))

