all: build

NAME=pcap
J=4

UNIX ?= $(shell if ocamlfind query lwt.unix >/dev/null 2>&1; then echo --enable-unix; fi)
MIRAGE ?= $(shell if ocamlfind query mirage-net >/dev/null 2>&1; then echo --enable-mirage; fi)

setup.ml: _oasis
	oasis setup

setup.data: setup.ml
	ocaml setup.ml -configure $(UNIX) $(MIRAGE)

build: setup.data setup.ml
	ocaml setup.ml -build -j $(J)

doc: setup.data setup.ml
	ocaml setup.ml -doc -j $(J)

install: setup.data setup.ml
	ocaml setup.ml -install

test: setup.ml build
	ocaml setup.ml -test

reinstall: setup.ml
	ocamlfind remove $(NAME) || true
	ocaml setup.ml -reinstall

clean:
	ocamlbuild -clean
	rm -f setup.data setup.log
