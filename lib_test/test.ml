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
	  assert_equal ~msg:"endian" ~printer:string_of_endian H.endian Little
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
