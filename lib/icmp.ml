(*
 * Copyright (c) 2013 Richard Mortier <mort@cantab.net>
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

open Printf

type bytes = Cstruct.t

[%%cenum
type typ =
  | ECHO_REPLY      [@id 0]
  | DSTUNREACH      [@id 3]
  | SRC_QUENCH      [@id 4]
  | REDIRECT        [@id  5]
  | ECHO            [@id  8]
  | RTR_SOLICIT     [@id 10]
  | TIME_EXCEEDED   [@id  11]
  | PARAM_PROBLEM   [@id  12]
  | TIMESTAMP       [@id  13]
  | TIMESTAMP_REPLY [@id  14]
  | INFO_REQUEST    [@id  15]
  | INFO_REPLY      [@id 16]
[@@uint8_t]]

[%%cenum
type redirect_code =
  | NET      [@id  0]
  | HOST     [@id  1]
  | TOS_NET  [@id  2]
  | TOS_HOST [@id 3]
[@@uint8_t]]

[%%cenum
type dstunreach_code =
  | NET         [@id   0]
  | HOST        [@id   1]
  | PROTO       [@id   2]
  | PORT        [@id   3]
  | FRAGREQ     [@id   4]
  | SRCRTFAIL   [@id   5]
  | ADMINPROHIB [@id 10]
[@@uint8_t]]

[%%cstruct
type icmp = {
  typ:  uint8_t;
  code: uint8_t;
  xsum: uint16_t;
} [@@big_endian]]

type h = {
  typ: int;
  code: int;
  xsum: int;
}

let h buf =
  { typ = get_icmp_typ buf;
    code = get_icmp_code buf;
    xsum = get_icmp_xsum buf;
  }

let format_typ_code h =
  match int_to_typ h.typ with
  | None -> (sprintf "#%d" h.typ), (sprintf "#%d" h.code)
  | Some v -> (typ_to_string v), (match v with
      | REDIRECT -> (match int_to_redirect_code h.code with
          | None -> sprintf "#%d" h.code
          | Some v -> redirect_code_to_string v
        )
      | _ -> (sprintf "#%d" h.code)
    )

let h_to_str h =
  let typ, code = format_typ_code h in
  sprintf "%s,%s, %04x" typ code h.xsum

let h_to_string h =
  let typ, code = format_typ_code h in
  sprintf "type:%s code:%s xsum:%04x" typ code h.xsum

type p = UNKNOWN of Cstruct.t
type t = h * p

let to_str (h, UNKNOWN p) = sprintf "ICMP(%s)" (h_to_str h)
let to_string (h, UNKNOWN p) =
  sprintf "ICMP(%s)|%s" (h_to_string h) (Buf.to_string "\n\t" p)
