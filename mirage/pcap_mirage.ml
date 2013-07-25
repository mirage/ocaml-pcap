(*
 * Copyright (c) 2012 Citrix Systems
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

open Lwt
open OS
open Pcap
open Pcap.LE (* write in little-endian format *)

let capture_limit = 64
(** Buffer this many packets before we start to drop *)

(* We lack a decent file abstraction so we'll experiment with representing
   open files as threads which read commands from an mvar. *)

type fd = Cstruct.t list option Lwt_mvar.t

let write fd bufs = Lwt_mvar.put fd (Some bufs)

let open_device blkif : fd =
  let m : fd = Lwt_mvar.create_empty () in
  let page_offset = ref 0L in
  let buf_offset = ref 0 in
  let closed = ref false in
  let buf = Cstruct.of_bigarray (Io_page.get 1) in
  let (_: unit Lwt.t) =
    while_lwt not(!closed) do
      Lwt_mvar.take m >>=
      function
      | None ->
        closed := true;
        return ()
      | Some (frags: Cstruct.t list) ->
        let single_write frag =
          let available_space = 4096 - !buf_offset in
          let needed_space = Cstruct.len frag in
          if needed_space >= available_space then begin
            Cstruct.blit frag 0 buf !buf_offset available_space;
            lwt () = blkif#write_page !page_offset buf in
            page_offset := Int64.add !page_offset 4096L;
            buf_offset := 0;
            return available_space
          end else begin
            Cstruct.blit frag 0 buf !buf_offset needed_space;
            buf_offset := !buf_offset + needed_space;
            return needed_space
          end in
        let write frag =
          let remaining = ref frag in
          while_lwt Cstruct.len !remaining > 0 do
            lwt written = single_write !remaining in
            remaining := Cstruct.shift !remaining written;
            return ()
          done in
        Lwt_list.iter_s write frags  
    done in
  m

let start_capture (input: Net.Ethif.t) fd =
  let stream, push = Lwt_bounded_stream.create capture_limit in

  Net.Ethif.set_promiscuous input (function
   | Net.Ethif.Input buf ->
      push (Some (OS.Clock.time (), [ buf ]));
      (* since this was an input frame, we want to process it as normal *)
      Net.Ethif.default_process input buf
   | Net.Ethif.Output bufs ->
      push (Some (OS.Clock.time (), bufs));
      return ()
  );

  let buf = OS.Io_page.get () in
  set_pcap_header_magic_number buf magic_number;
  set_pcap_header_version_major buf major_version;
  set_pcap_header_version_minor buf minor_version;
  set_pcap_header_thiszone buf 0l;
  set_pcap_header_sigfigs buf 0l;
  set_pcap_header_snaplen buf 4096l;
  set_pcap_header_network buf (Network.(to_int32 Ethernet));
  lwt () = write fd [Cstruct.sub buf 0 sizeof_pcap_header] in

  try_lwt
    while_lwt true do
      lwt packets = Lwt_bounded_stream.nget 1 stream in
      Lwt_list.iter_s
        (fun (time, frags) ->
          let len = List.fold_left (+) 0 (List.map Cstruct.len frags) in
          let buf = OS.Io_page.get () in
          set_pcap_packet_ts_sec buf (Int32.(of_float time));
          set_pcap_packet_ts_usec buf (Int32.rem (Int32.of_float ( time *. 1000000.)) 1000000l);
          set_pcap_packet_incl_len buf (Int32.of_int len);
          set_pcap_packet_orig_len buf (Int32.of_int len);
          write fd (Cstruct.sub buf 0 sizeof_pcap_packet :: frags)
        ) packets
    done
  with Lwt_stream.Closed ->
    return ()
