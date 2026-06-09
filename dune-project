(lang dune 3.23)

(implicit_transitive_deps false)

(generate_opam_files true)

(name sigv4)

(source
 (github lmdexpr/sigv4.ml))

(license MIT)

(authors "Yuki Tajiri")

(maintainers "Yuki Tajiri")

(package
 (name sigv4)
 (synopsis "AWS Signature Version 4 (header-based signing), I/O-agnostic")
 (description
  "A pure OCaml implementation of AWS SigV4 header signing. It performs no HTTP\nrequests, no credential fetching, and no clock reads: the caller injects time,\ncredentials, and the request to be signed. Conforms to the AWS SigV4 v4 test\nsuite (header signing). Runtime dependencies are limited to uri and digestif.")
 (depends
  (ocaml
   (>= 5.3.0))
  dune
  uri
  digestif
  (alcotest :with-test)
  (yojson :with-test)))

(package
 (name sigv4-cohttp-eio)
 (synopsis "Cohttp-eio adapter for sigv4 (AWS container credentials provider)")
 (description
  "Wires Sigv4.Credentials.handler to the AWS container credentials endpoint\n(ECS link-local) using a cohttp-eio client, with a dummy fallback for local\ndevelopment. Kept separate from the core sigv4 package so that callers that\nonly need signing do not pull in eio and cohttp.")
 (depends
  (ocaml
   (>= 5.3.0))
  dune
  (sigv4
   (= :version))
  eio
  cohttp-eio
  uri
  yojson))
