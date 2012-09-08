(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 *           (c) 2012 Citrix Systems
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

open Pcap
open Printf

let parse filename =
  printf "filename: %s\n" filename;
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  printf "total pcap file length %d\n" (Cstruct.len buf);

  let header, body = Cstruct.split buf sizeof_pcap_header in
  print_pcap_header header;

  let packets = Cstruct.iter 
    (fun buf -> Some (sizeof_pcap_packet + (Int32.to_int (get_pcap_packet_incl_len buf))))
    (fun buf -> buf, (Cstruct.shift buf sizeof_pcap_packet))
    body
  in 
  let num_packets = Cstruct.fold
    (fun a packet -> print_pcap_packet packet; (a+1)) 
    packets 0
  in
  printf "num_packets %d\n" num_packets

let _ =
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files)
    "Dump the contents of pcap files";
  let files = List.rev !files in
  List.iter parse files
