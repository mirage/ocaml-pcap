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
open Net.Ethif
open Pcap

(* We lack a decent file abstraction so we'll experiment with representing
   open files as threads which read commands from an mvar. *)

type fd = Cstruct.buf option Lwt_mvar.t

let open_blkif blkif : fd =
  let m : fd = Lwt_mvar.create_empty () in
  let offset = ref 0L in
  let closed = ref false in
  let buf = Io_page.get () in
  let (_: unit Lwt.t) =
    while_lwt not(!closed) do
      Lwt_mvar.take m >>=
      function
      | None ->
        closed := true;
        return ()
      | Some (frag: Cstruct.buf) ->
        (* Copy into 'buf', effectively padding to a whole page *)
        Cstruct.blit_buffer frag 0 buf 0 (Cstruct.len buf);
        lwt () = blkif#write_page !offset buf in
        offset := Int64.(add !offset (of_int (Cstruct.len frag)));
        return ()
    done in
  m

let capture input fd =
  let buf = OS.Io_page.get () in
  set_pcap_header_magic_number buf magic_number_littleendian;
  set_pcap_header_version_major buf major_version;
  set_pcap_header_version_minor buf minor_version;
  set_pcap_header_thiszone buf 0l;
  set_pcap_header_sigfigs buf 0l;
  set_pcap_header_snaplen buf 4096l;
  set_pcap_header_network buf network_ethernet;
  lwt () = Lwt_mvar.put fd (Some(Cstruct.sub buf 0 sizeof_pcap_header)) in

  let stream = get_captured_packets input in
  try_lwt
    while_lwt true do
      let batchsize = 16 in
      lwt packets = Lwt_bounded_stream.nget batchsize stream in
      Lwt_list.iter_s
        (fun (time, packet) ->
          set_pcap_packet_ts_sec buf (Int32.(of_float time));
          set_pcap_packet_ts_usec buf (Int32.rem (Int32.of_float (time *. 1000000.)) 1000000l);
          set_pcap_packet_incl_len buf (Int32.of_int (Cstruct.len packet));
          set_pcap_packet_orig_len buf (Int32.of_int (Cstruct.len packet));
          lwt () = Lwt_mvar.put fd (Some(Cstruct.sub buf 0 sizeof_pcap_packet)) in
          Lwt_mvar.put fd (Some packet);
        ) packets
    done
  with Lwt_stream.Closed ->
    return ()
