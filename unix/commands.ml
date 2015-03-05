(*
 * Copyright (c) 2014 Richard Mortier <mort@cantab.net>
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

open Copts

(* conditional printers, conditioned on copts *)
let pr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.fprintf stderr
  | Verbose -> Printf.fprintf stderr
let vpr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.ifprintf stderr
  | Verbose -> Printf.fprintf stderr

let print copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let open Printf in
  let files = List.map Trace.of_filename filenames in
  List.iter (fun (file, packets) ->
      printf "### START: filename:%s size:%d\n%!"
        file.Trace.filename file.Trace.filesize;
      let npackets =
        Cstruct.fold (fun acc pkt ->
            let Ocap.PKT(h, p, _) = pkt in
            let ocap_to_str, pkt_to_str =
              match copts.verbosity with
              | Quiet | Normal -> Ocap.to_str, Packet.to_str
              | Verbose -> Ocap.to_string, Packet.to_string
            in
            printf "%d: PKT(%s)%s\n%!" acc (ocap_to_str h) (pkt_to_str p);
            acc+1
          ) packets 0
      in
      printf "### END: npackets:%d\n%!" npackets
    ) files

let reform copts filenames ofilename =
  let _pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let write fd buf =
    let s = Cstruct.to_string buf in
    Unix.write fd s 0 (String.length s)
  in

  let creat filename =
    let fd = Unix.(openfile filename [O_WRONLY; O_CREAT; O_TRUNC] 0o644) in
    let buf = Cstruct.create Pcap.sizeof_pcap_header in
    let open Pcap in (* assume LE platform for now *)
    LE.set_pcap_header_magic_number  buf magic_number;
    LE.set_pcap_header_version_major buf major_version;
    LE.set_pcap_header_version_minor buf minor_version;
    LE.set_pcap_header_thiszone      buf 0x0000_0000_l; (* GMT *)
    LE.set_pcap_header_sigfigs       buf 0x0000_0000_l;
    LE.set_pcap_header_snaplen       buf 0x0000_ffff_l;
    LE.set_pcap_header_network       buf 0x0000_0001_l;
    let n = write fd buf in
    assert (n = 24);
    fd
  in

  let ofd = creat ofilename in
  let ifds = filenames |> List.map (fun fn ->
      (* assumes all inputs are valid pcap trace files *)
      let (_, ifd) = Trace.of_filename fn in
      ifd
    )
  in

  let streams = List.map (fun ifd -> (ifd (), ifd)) ifds in

  let process streams =
    let open Ocap in
    let cmp (lp,_) (rp,_) = match lp, rp with
      | None, _ -> -1
      | _, None -> 1
      | Some (PKT (lh, _, _)), Some (PKT (rh, _, _)) -> compare lh rh
    in
    let rec process_ ss =
      match List.sort cmp ss with
      | [] -> ()
      | (p,s) :: tl ->
        let rest = match p with
          | None -> tl
          | Some PKT(h,b,bs) ->
            let buf = Cstruct.create Pcap.sizeof_pcap_packet in
            let open Pcap in (* LE platform assumed above *)
            let secs = Int64.(div h.usecs 1_000_000_L |> to_int32) in
            let usecs = Int64.(rem h.usecs 1_000_000_L |> to_int32) in
            LE.set_pcap_packet_ts_sec buf secs;
            LE.set_pcap_packet_ts_usec buf usecs;
            LE.set_pcap_packet_caplen buf (Int32.of_int h.caplen);
            LE.set_pcap_packet_len buf (Int32.of_int h.len);
            let n = write ofd buf in assert (n=16);
            let n = write ofd bs in assert (n=Cstruct.len bs);
            (s (), s) :: tl
        in process_ rest
    in
    process_ streams
  in
  process streams

type time_t = {
  secs: int32;
  usecs: int32;
}
let time_t_to_string t =
  Printf.sprintf "%ld.%06ld" t.secs t.usecs

type statistics = {
  mutable packets: int32;
  mutable bytes: int32;
  mutable capbytes: int32;
  mutable first: int64;
  mutable last: int64;
}
let statistics_to_string s =
  Printf.sprintf
    "npackets:%ld bytes:%ld capbytes:%ld first:%s last:%s"
    s.packets s.bytes s.capbytes
    (Ocap.usecs_to_string s.first) (Ocap.usecs_to_string s.last)

let statistics copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  let files = List.map Trace.of_filename filenames in
  List.iter (fun (file, packets) ->
      let zero = { packets=0l;
                   bytes=0l;
                   capbytes=0l;
                   first=0L;
                   last=0L
                 }
      in
      let stats =
        Cstruct.fold (fun s pkt ->
            let open Ocap in
            let PKT(h,_,_) = pkt in
            s.packets <- Int32.add s.packets 1l;
            s.bytes <- Int32.(add s.bytes (of_int h.len));
            s.capbytes <- Int32.(add s.capbytes (of_int h.caplen));
            if s.first = 0L then s.first <- h.usecs;
            s.last <- h.usecs;
            s
          ) packets zero
      in
      Printf.printf "filename:%s %s\n%!"
        file.Trace.filename (statistics_to_string stats)
    ) files

let help copts man_format cmds topic =
  let _pr, _vpr = pr copts, vpr copts in
  match topic with
  | None -> `Help (`Pager, None)
  | Some topic ->
    let topics = "topics" :: "patterns" :: "environment" :: cmds in
    let conv, _ = Cmdliner.Arg.enum (List.rev_map (fun s -> (s, s)) topics) in
    match conv topic with
    | `Error e -> `Error (false, e)
    | `Ok t when t = "topics" -> List.iter print_endline topics; `Ok ()
    | `Ok t when List.mem t cmds -> `Help (man_format, Some t)
    | `Ok t ->
      let page = (topic, 7, "", "", ""), [`S topic; `P "Say something";] in
      `Ok (Cmdliner.Manpage.print man_format Format.std_formatter page)
