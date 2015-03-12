(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (C) 2012 Citrix Systems Inc
 * Copyright (C) 2013 Richard Mortier <mort@cantab.net>
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

let major_version = 2

let minor_version = 4

let magic_number = 0xa1b2c3d4_l

type endian = | Big | Little

let string_of_endian = function
  | Big    -> "big"
  | Little -> "little"
let endian_to_string = string_of_endian

(* The pcap format allows the writer to use either big- or little- endian,
   depending on which is most convenient (higher performance). We are able to
   read both, but we haven't optimised the low-level set_* functions enough to
   make it worthwhile to bother detecting native endian-ness and switching.
*)

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
    uint32_t caplen;         (* number of octets of packet saved in file *)
    uint32_t len             (* actual length of packet *)
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
    uint32_t caplen;         (* number of octets of packet saved in file *)
    uint32_t len             (* actual length of packet *)
  } as big_endian
end

let sizeof_pcap_header = BE.sizeof_pcap_header (* = LE.sizeof_pcap_header *)

let sizeof_pcap_packet = BE.sizeof_pcap_packet (* = LE.sizeof_pcap_packet *)

module type HDR = sig
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

type fh = {
  magic_number: int32;
  endian: endian;
  version_major: int;
  version_minor: int;
  timezone: int32;     (* GMT to local correction *)
  sigfigs: int32;      (* accuracy of timestamps *)
  snaplen: int32;      (* max length of captured packets, in octets *)
  network: int32       (* data link type *)
}

let fh_to_str fh =
  sprintf "%d.%d/%s, %lu, %lu, %lu, %lu"
    fh.version_major fh.version_minor (string_of_endian fh.endian)
    fh.timezone fh.sigfigs fh.snaplen fh.network

let fh_to_string fh =
  sprintf "magic_number:%.8lx endian:%s version_major:%d version_minor:%d \
           timezone:%lu sigfigs:%lu snaplen:%lu lltype:%lu"
    fh.magic_number (string_of_endian fh.endian)
    fh.version_major fh.version_minor
    fh.timezone fh.sigfigs fh.snaplen fh.network

type h = {
  secs: int32;
  usecs: int32;
  caplen: int;
  len: int;
}

let to_str h =
  sprintf "%lu.%06lu %u[%u]" h.secs h.usecs h.caplen h.len

let to_string h =
  sprintf "secs:%lu usecs:%lu caplen:%u len:%u" h.secs h.usecs h.caplen h.len

type t = PCAP of h * Packet.t * Cstruct.t

let iter buf demuxf =
  let pcap_hdr =
    let le_magic = LE.get_pcap_header_magic_number buf in
    let be_magic = BE.get_pcap_header_magic_number buf in
    if le_magic = magic_number then Some (module LE: HDR)
    else if be_magic = magic_number then Some (module BE: HDR)
    else None
  in
  match pcap_hdr with
  | None -> None
  | Some h ->
    let module H = (val h : HDR) in

    let h buf =
      { secs = H.get_pcap_packet_ts_sec buf;
        usecs = H.get_pcap_packet_ts_usec buf;
        caplen = H.get_pcap_packet_caplen buf |> Int32.to_int;
        len = H.get_pcap_packet_len buf |> Int32.to_int
      }
    in

    let fh =
      { magic_number = H.get_pcap_header_magic_number buf;
        endian = H.endian;
        version_major = H.get_pcap_header_version_major buf;
        version_minor = H.get_pcap_header_version_minor buf;
        timezone = H.get_pcap_header_thiszone buf;
        sigfigs = H.get_pcap_header_sigfigs buf;
        snaplen = H.get_pcap_header_snaplen buf;
        network = H.get_pcap_header_network buf;
      }
    in
    let _, buf = Cstruct.split buf sizeof_pcap_header in

    Some (
      fh, Seq.iter
            (fun buf ->
               let offset_delta =
                 sizeof_pcap_packet
                 + (Int32.to_int (H.get_pcap_packet_caplen buf))
               in
               Some offset_delta
            )
            (fun buf ->
               let hdr = h buf in
               let buf = Cstruct.shift buf sizeof_pcap_packet in
               let payload = demuxf buf in
               PCAP(hdr, payload, buf)
            )
            buf
    )

let to_pkt = function
  | PCAP ({ secs; usecs; caplen; len}, p, buf) ->
    let usecs =
      let open Int64 in
      let secs, usecs = of_int32 secs, of_int32 usecs in
      add usecs (mul secs 1_000_000L)
    in
    let open Ocap in
    PKT ({ usecs; caplen; len }, p, buf)
