(*
 * Copyright (C) Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

open Pcap
open OUnit

let ( |> ) a b = b a
let id x = x

let example_file = "lib_test/dhcp.pcap"

(* Note this will leak fds and memory *)

let open_file filename =
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1))

let header () =
  let buf = open_file example_file in
  match Pcap.detect buf with
  | Some h ->
	  let module H = (val h: HDR) in
	  assert_equal ~msg:"endian"        ~printer:string_of_endian H.endian                             Little;
	  assert_equal ~msg:"version_major" ~printer:string_of_int   (H.get_pcap_header_version_major buf) 2;
	  assert_equal ~msg:"version_minor" ~printer:string_of_int   (H.get_pcap_header_version_minor buf) 4;
	  assert_equal ~msg:"thiszone"      ~printer:Int32.to_string (H.get_pcap_header_thiszone buf)      0l;
	  assert_equal ~msg:"sigfigs"       ~printer:Int32.to_string (H.get_pcap_header_sigfigs buf)       0l;
	  assert_equal ~msg:"snaplen"       ~printer:Int32.to_string (H.get_pcap_header_snaplen buf)       65535l;
	  assert_equal ~msg:"network"       ~printer:Int32.to_string (H.get_pcap_header_network buf)       1l;
  | None ->
	  failwith (Printf.sprintf "failed to parse pcap header from %s" example_file)


let _ =
  let verbose = ref false in
  Arg.parse [
    "-verbose", Arg.Unit (fun _ -> verbose := true), "Run in verbose mode";
  ] (fun x -> Printf.fprintf stderr "Ignoring argument: %s" x)
    "Test pcap parsing code";

  let suite = "pcap" >:::
    [
      "header" >:: header;
    ] in
  run_test_tt ~verbose:!verbose suite
