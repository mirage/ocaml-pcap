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

cstruct udp4 {
  uint16_t srcpt;
  uint16_t dstpt;
  uint16_t len;
  uint16_t xsum
} as big_endian

type h = {
  srcpt: int;
  dstpt: int;
  len: int;
  xsum: int
}

let h buf =
  { srcpt = get_udp4_srcpt buf;
    dstpt = get_udp4_dstpt buf;
    len = get_udp4_len buf;
    xsum = get_udp4_xsum buf;
  }

let to_str h = sprintf "%d,%d" h.srcpt h.dstpt

let to_string h =
  sprintf "src:%d dst:%d len:%d xsum:%04x" h.srcpt h.dstpt h.len h.xsum
