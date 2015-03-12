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

cenum typ {
  ECHO_REPLY  =  0;
  DSTUNREACH  =  3;
  SRC_QUENCH  =  4;
  REDIRECT    =  5;
  ECHO        =  8;
  RTR_SOLICIT = 10;
  TIME_EXCEEDED   = 11;
  PARAM_PROBLEM   = 12;
  TIMESTAMP       = 13;
  TIMESTAMP_REPLY = 14;
  INFO_REQUEST    = 15;
  INFO_REPLY      = 16
} as uint8_t

cenum redirect_code {
  NET      = 0;
  HOST     = 1;
  TOS_NET  = 2;
  TOS_HOST = 3
} as uint8_t

cenum dstunreach_code {
  NET         =  0;
  HOST        =  1;
  PROTO       =  2;
  PORT        =  3;
  FRAGREQ     =  4;
  SRCRTFAIL   =  5;
  ADMINPROHIB = 10
} as uint8_t

cstruct icmp {
  uint8_t typ;
  uint8_t code;
  uint16_t xsum
} as big_endian

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
