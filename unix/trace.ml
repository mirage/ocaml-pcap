(*
 * Copyright (c) 2014-2015 Richard Mortier <mort@cantab.net>
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

type metadata = {
  filename: string;
  filesize: int;
}

type t = metadata * Ocap.t Seq.t

let kB = 1024
let mB = 1024*kB
let buffer_size = 4*mB

let buf_of_filename filename =
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  Bigarray.(Array1.map_file fd char c_layout false (-1)) |> Cstruct.of_bigarray

let pcap_of_filename filename =
  let buf = buf_of_filename filename in
  let filesize = Cstruct.len buf in

  let open Ocap in
  match Pcap.iter buf (Demux.(eth_demux () ethertype_demux)) with
  | None -> failwith "PCAP error: failed to read magic number!"
  | Some (fh, packets) -> { filename; filesize }, fh, packets

let erf_of_filename filename =
  let buf = buf_of_filename filename in
  let filesize = Cstruct.len buf in

  let open Ocap in
  match Erf.iter buf (Demux.(eth_demux () ethertype_demux)) with
  | None -> failwith "ERF error: failed to open file!"
  | Some (_, packets) -> { filename; filesize }, packets

let of_filename filename =
  let suffix = Filename.check_suffix filename in
  if suffix ".pcap" then
    let metadata, fileheader, packets = pcap_of_filename filename in
    (metadata, Seq.map Pcap.to_pkt packets)
  else if suffix ".erf" then
    let metadata, packets = erf_of_filename filename in
    (metadata, Seq.map Erf.to_pkt packets)
  else
    failwith "unrecognised suffix!"
