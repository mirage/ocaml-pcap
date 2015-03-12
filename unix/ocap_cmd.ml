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
open Copts

let version = "0.1+" ^ Ocap.version

let str = Printf.sprintf

let help_sects = [
  `S copts_sect;
  `P "These options are common to all commands.";
  `S "MORE HELP";
  `P " `$(mname) $(i,COMMAND) --help' for help on a single command."; `Noblank;
  `P " `$(mname) help print' for help on displaying captures."; `Noblank;
  `P " `$(mname) help reform' for help on reforming capture files."; `Noblank;
  `P " `$(mname) help statistics' for help on capture file statistics.";
  `S "BUGS"; `P "Check bug reports at http://github.com/mor1/ocap/issues/.";
]

let print_t =
  let filenames =
    Arg.(value & (pos_all file) [] & info [] ~docv:"FILENAMEs")
  in
  let doc = "render a capture file to stdout" in
  let man =
    [`S "DESCRIPTION";
     `P "Renders a capture file to stdout. Readability can be improved by\n\
         piping through \
         $(i, gawk -- '{  gsub(\"\\\\\\\\|\", \"\\\\n\\\\t|\"); print \\$0 }')\
        "
    ] @ help_sects
  in
  Term.(pure Commands.print $ copts_t $ filenames),
  Term.info "print" ~doc ~sdocs:copts_sect ~man

let reform_t =
  let filenames =
    Arg.(non_empty & (pos_left ~rev:true 0 file) [] & info [] ~docv:"FILENAMEs")
  in
  let ofilename =
    Arg.(required & pos ~rev:true 0 (some string) None
         & info [] ~docv:"FILENAME")
  in
  let doc = "split/merge capture files" in
  let man =
    [`S "DESCRIPTION";
     `P "Split or merge capture files. ..."] @ help_sects
  in
  Term.(pure Commands.reform $ copts_t $ filenames $ ofilename),
  Term.info "reform" ~doc ~sdocs:copts_sect ~man

let statistics_t =
  let filenames =
    Arg.(value & (pos_all file) [] & info [] ~docv:"FILENAMEs")
  in
  let doc = "render capture file statistics" in
  let man =
    [`S "DESCRIPTION";
     `P "Renders statistics about a capture file. ..."] @ help_sects
  in
  Term.(pure Commands.statistics $ copts_t $ filenames),
  Term.info "statistics" ~doc ~sdocs:copts_sect ~man

let help_t =
  let topic =
    let doc = "The topic to get help on. `topics' lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  let doc = "display help about ocap commands and common options" in
  let man =
    [`S "DESCRIPTION";
     `P "Prints help about ocap commands and common options..."] @ help_sects
  in
  Term.(ret (pure Commands.help
             $ copts_t $ Term.man_format $ Term.choice_names $ topic)),
  Term.info "help" ~doc ~man

let default_cmd =
  let doc = "capture file manipulation" in
  let man = help_sects in
  Term.(ret (pure (fun _ -> `Help (`Pager, None)) $ copts_t)),
  Term.info "ocap" ~version:version ~sdocs:copts_sect ~doc ~man

let cmds = [ print_t; reform_t; statistics_t; help_t ]

let () =
  match Term.eval_choice default_cmd cmds with
  | `Error _ -> exit 1
  | _ -> exit 0
