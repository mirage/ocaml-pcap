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

type 'a t
(** Similar to Lwt_stream.bounded_push except threads never block in push() *)

val create: int -> 'a t * ('a option -> unit)
(** [create max_elements] creates a stream which can contain at most
    [max_elements] *)

val get_available: 'a t -> 'a list
(** [get_available t] returns all available elements from [t] without blocking *)

val nget: int -> 'a t -> 'a list Lwt.t
(** [nget n t] returns [n] elements from [t] *)

val set_max_elements: int -> 'a t -> unit
(** [set_max_elements n t] resets the maximum number of elements stored within
    [t] to [n]. If more than [n] elements are stored then the surplus elements
    will be immediately dropped. *)
