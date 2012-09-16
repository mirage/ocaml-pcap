val major_version: int

val minor_version: int

type endian =
| Big
| Little

val string_of_endian : endian -> string

val sizeof_pcap_header: int

val sizeof_pcap_packet: int

module type HDR = sig
  val endian: endian

  val get_pcap_header_magic_number: Cstruct.buf -> int32
  val get_pcap_header_version_major: Cstruct.buf -> int
  val get_pcap_header_version_minor: Cstruct.buf -> int
  val get_pcap_header_thiszone: Cstruct.buf -> int32
  val get_pcap_header_sigfigs: Cstruct.buf -> int32
  val get_pcap_header_snaplen: Cstruct.buf -> int32
  val get_pcap_header_network: Cstruct.buf -> int32

  val set_pcap_header_magic_number: Cstruct.buf -> int32 -> unit
  val set_pcap_header_version_major: Cstruct.buf -> int -> unit
  val set_pcap_header_version_minor: Cstruct.buf -> int -> unit
  val set_pcap_header_thiszone: Cstruct.buf -> int32 -> unit
  val set_pcap_header_sigfigs: Cstruct.buf -> int32 -> unit
  val set_pcap_header_snaplen: Cstruct.buf -> int32 -> unit
  val set_pcap_header_network: Cstruct.buf -> int32 -> unit

  val get_pcap_packet_ts_sec: Cstruct.buf -> int32
  val get_pcap_packet_ts_usec: Cstruct.buf -> int32
  val get_pcap_packet_incl_len: Cstruct.buf -> int32
  val get_pcap_packet_orig_len: Cstruct.buf -> int32

  val set_pcap_packet_ts_sec: Cstruct.buf -> int32 -> unit
  val set_pcap_packet_ts_usec: Cstruct.buf -> int32 -> unit
  val set_pcap_packet_incl_len: Cstruct.buf -> int32 -> unit
  val set_pcap_packet_orig_len: Cstruct.buf -> int32 -> unit

end

val detect: Cstruct.buf -> (module HDR) option

val packets: (module HDR) -> Cstruct.buf -> (Cstruct.buf * Cstruct.buf) Cstruct.iter

