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

type 'a t = {
  stream: 'a Lwt_stream.t;
  max_elements: int ref;
  nr_elements: int ref;
  nr_dropped: int ref;
}

let create max_elements =
  let stream, stream_push = Lwt_stream.create () in
  let t = {
    stream = stream;
    max_elements = ref max_elements;
    nr_elements = ref 0;
    nr_dropped = ref 0;
  } in
  let push = function
    | None -> stream_push None
    | Some x ->
      if !(t.nr_elements) > !(t.max_elements)
      then begin
        incr t.nr_dropped;
      end else begin
        stream_push (Some x);
        incr t.nr_elements
      end in
  t, push

let get_available t =
  let all = Lwt_stream.get_available t.stream in
  t.nr_elements := !(t.nr_elements) - (List.length all);
  all

let nget n t =
  lwt all = Lwt_stream.nget n t.stream in
  t.nr_elements := !(t.nr_elements) - (List.length all);
  return all

let set_max_elements max_elements t =
  t.max_elements := max_elements;
  (* drop elements if we have too many *)
  let excess_elements = max 0 (!(t.nr_elements) - max_elements) in
  if excess_elements > 0 then begin
    let (_: 'a list) = Lwt_stream.get_available_up_to excess_elements t.stream in
    t.nr_elements := max_elements
  end
