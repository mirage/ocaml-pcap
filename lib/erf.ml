(*
 * Copyright (C) 2015 Richard Mortier <mort@cantab.net>
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

(** http://wiki.wireshark.org/ERF *)

open Printf
let ( &&& ) x y = Int64.logand x y

module Time = struct

  let to_usecs ts =
    let open Int64 in
    let ( >>> ) x y = Int64.shift_right_logical x y in
    let ( <<< ) x y = Int64.shift_left x y in (* >> *)
    let ( +++ ) x y = Int64.add x y in
    let ( --- ) x y = Int64.sub x y in
    let ( *** ) x y = Int64.mul x y in

    let secs = (ts >>> 32) in

    let usecs =
      let usecs = (ts &&& 0xFFFF_FFFF_L) *** 1_000_000_L in
      (usecs +++ ((usecs &&& 0x8000_0000_L) <<< 1)) >>> 32
    in

    let secs,usecs =
      if usecs >= 1_000_000L then secs+++1L, usecs---1_000_000L else secs,usecs
    in
    (secs *** 1_000_000_L) +++ usecs

end

module Flags = struct
  let ifnum     fs = fs land 0x03
  let is_vlen   fs = fs land 0x04 <> 0
  let is_trunc  fs = fs land 0x08 <> 0 (* deprecated *)
  let is_rxerr  fs = fs land 0x10 <> 0
  let is_interr fs = fs land 0x20 <> 0 (* not present on wire *)
  let is_exth   fs = fs land 0x80 <> 0

  let to_string fs =
    sprintf "%u%s%s%s%s%s"
      (ifnum fs)
      (if is_vlen fs then "V" else ".")
      (if is_trunc fs then "T" else ".")
      (if is_rxerr fs then "R" else ".")
      (if is_interr fs then "I" else ".")
      (if is_exth fs then "X" else ".")

end

cstruct erf_ts {
  uint64_t ts;
} as little_endian

cstruct erf_packet {
  uint8_t typ;
  uint8_t flags;
  uint16_t rlen;
  uint16_t lctr;
  uint16_t wlen;
  uint16_t chaff (* assumes ERF:ETH (typ=0x02) *)
} as big_endian

type h = {
  usecs: int64;
  flags: int;
  rlen: int;
  lctr: int;
  wlen: int;
}

let h_to_str h =
  sprintf "%s, %s, %u,%u,%u"
    (Ocap.usecs_to_string h.usecs) (Flags.to_string h.flags)
    h.rlen h.lctr h.wlen

let h_to_string h =
  sprintf "time:%s type:%02x flags:%08x rlen:%u lctr:%u wlen:%u"
    (Ocap.usecs_to_string h.usecs) h.flags h.rlen h.lctr h.wlen

type t = ERF of h * Packet.t * Cstruct.t

let iter buf demuxf =
  let h buf =
    let usecs = get_erf_ts_ts buf |> Time.to_usecs in
    let buf = Cstruct.shift buf sizeof_erf_ts in
    { usecs;
      flags = get_erf_packet_flags buf;
      rlen = get_erf_packet_rlen buf - sizeof_erf_ts - sizeof_erf_packet;
      lctr = get_erf_packet_lctr buf;
      wlen = get_erf_packet_wlen buf;
    }
  in

  Some (
    (),
    Seq.iter
      (fun buf ->
         let buf = Cstruct.shift buf sizeof_erf_ts in
         Some (get_erf_packet_rlen buf)
      )
      (fun buf ->
         let hdr = h buf in
         let buf = Cstruct.shift buf (sizeof_erf_ts + sizeof_erf_packet) in
         let payload = demuxf buf in
         ERF(hdr, payload, buf)
      )
      buf
  )

let to_pkt = function
  | ERF ({ usecs; flags; rlen; lctr; wlen }, p, buf) ->
    let open Ocap in
    PKT ({usecs; caplen=rlen; len=wlen}, p, buf)
