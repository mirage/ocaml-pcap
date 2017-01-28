#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  let opams =
    [ Pkg.opam_file "opam" ~lint_deps_excluding:(Some ["ppx_tools" ; "ounit" ; "oUnit"]) ]
  in
  Pkg.describe ~opams "pcap-format" @@ fun _ ->
  Ok [
    Pkg.mllib "lib/pcap.mllib";
    Pkg.test "lib_test/test"
  ]
