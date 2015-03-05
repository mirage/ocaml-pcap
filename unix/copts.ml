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

open Cmdliner

(* common options, following Cmdliner documentation *)
type verbosity = Quiet | Normal | Verbose
let verbosity_to_string = function
  | Quiet -> "quiet"
  | Normal -> "normal"
  | Verbose -> "verbose"

type copts = {
  verbosity: verbosity;
  debug: bool;
  no_progress: bool;
}

let copts verbosity debug no_progress = { verbosity; debug; no_progress }

let copts_sect = "COMMON OPTIONS"

let copts_t =
  let docs = copts_sect in
  let debug =
    let doc = "Include debug output." in
    Arg.(value & flag & info ["debug"] ~docs ~doc)
  in
  let verbose =
    let doc = "Suppress output." in
    let quiet = Quiet, Arg.info ["q"; "quiet"] ~docs ~doc in
    let doc = "Verbose output." in
    let verbose = Verbose, Arg.info ["v"; "verbose"] ~docs ~doc in
    Arg.(last & vflag_all [Normal] [quiet; verbose])
  in
  let no_progress =
    let doc = "Turn off progress indication." in
    Arg.(value & flag & info ["no-progress"] ~docs ~doc)
  in
  Term.(pure copts $ verbose $ debug $ no_progress)
