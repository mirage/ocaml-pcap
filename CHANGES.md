## v0.6.0 (2022-04-07)

* Remove the "build" directive on dune dependency (@CraigFE, #33)
* Remove unused "ppx_tools" dependency (@kit-ty-kate, #35)
* Remove "mmap" dependency, require OCaml 4.08.0 (@hannesm, #36)

## 0.5.2 (2019-05-27)

* port to dune (@avsm)
* upgrade metadata to opam 2.0 (@avsm)
* test on OCaml 4.07 (@avsm)

## 0.5.1 (2018-06-14)

* build with jbuilder

## 0.5.0 (2017-02-03)

* removed mirage and print sublibrary
* converted build system to topkg

## 0.4.0 (2016-04-30)

* add an opam file
* replace camlp4 with ppx
* add windows support

## 0.3.3 (2013-07-25)

* Add Lwt_bounded implementation to constrain size of packet captures.
* Update package name to pcap-format
* Update to new Cstruct (>= 0.6.0) and Mirage

## 0.3.1 (2012-09-18)

* Support dumping a pcap trace to a block device.
* Use `cstruct` signature generators to tidy up pcap interface.
* Initial public release.
