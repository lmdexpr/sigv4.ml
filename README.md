# sigv4.ml

An OCaml implementation of [AWS Signature Version 4][sigv4-spec] (header-based signing). 

The library is I/O-agnostic: it performs no HTTP requests, no credential fetching, and no clock reads.
The caller injects time, credentials, and the request to be signed.

Source: <https://github.com/lmdexpr/sigv4.ml>

[sigv4-spec]: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

## Status

Conforms to the [AWS SigV4 v4 test suite][awssuite] (header signing). All 38 fixtures pass.

[awssuite]: https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4

## Install

Not yet published to the opam repository. For now, pin it straight from GitHub:

```sh
# Core signing library (depends only on uri and digestif)
opam pin add sigv4 https://github.com/lmdexpr/sigv4.ml.git

# Optional cohttp-eio adapter (AWS container credentials provider)
opam pin add sigv4-cohttp-eio https://github.com/lmdexpr/sigv4.ml.git
```

Once it lands in the opam repository, `opam install sigv4` will work directly.

## Usage

```ocaml
let signed =
  (* Install a credentials provider for the dynamic extent of the continuation. 
     [Provider.static] is the simplest one; see "Credentials" below for the environment-variable and chain providers. *)
  Sigv4.with_provider
    (Sigv4.Provider.Static.make
       ~access_key:"AKIDEXAMPLE"
       ~secret_key:"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
       ())
  @@ fun () ->
  let credentials = Sigv4.Credentials.fetch () in
  Sigv4.sign
    ~now:Unix.time (* [now : unit -> float]; pass any UTC-epoch thunk *)
    ~credentials
    ~region:"us-east-1"
    ~service:"dynamodb"
    ~http_method:"POST"
    ~payload:body
    ~uri:(Uri.of_string "https://dynamodb.us-east-1.amazonaws.com/")
    [ "Host", "dynamodb.us-east-1.amazonaws.com";
      "Content-Type", "application/x-amz-json-1.0";
      "X-Amz-Target", "DynamoDB_20120810.PutItem" ]

(* [signed] is the list of headers to ADD to the request:
   - "Authorization": "AWS4-HMAC-SHA256 Credential=... Signature=..."
   - "X-Amz-Date": "20260101T000000Z"
   - "X-Amz-Security-Token": ... (only when session_token is present)
   - "X-Amz-Content-Sha256": ... (only when ~signed_body_header:true) *)
```

## Credentials

Credentials are resolved through a small **provider** abstraction.
A `Sigv4.Provider.t` either yields credentials or *declines* with a reason; `Sigv4.Provider.chain` tries providers left to right and the first that resolves wins.
`Sigv4.with_provider` installs a provider for the dynamic extent of a continuation, where `Sigv4.Credentials.fetch ()` produces the resolved (abstract) credentials.
If every provider in the chain declines, `Sigv4.No_credentials` is raised at the `fetch` site, with each provider's decline reason aggregated in the message.

| Provider | Library | Notes |
|---|---|---|
| `Sigv4.Provider.Static.make ~access_key ~secret_key ?session_token ()` | `sigv4` (core) | Fixed credentials; ideal for tests and local development. |
| `Sigv4.Provider.Env.make ?getenv ()` | `sigv4` (core) | Reads `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`). `?getenv` defaults to `Sys.getenv_opt`. |
| `Sigv4_cohttp_eio.Ecs.make ~now ~client` | `sigv4-cohttp-eio` | AWS container credentials endpoint (ECS); caches until near expiry. |

```ocaml
(* env first, then explicit static credentials as a fallback *)
let provider =
  Sigv4.Provider.chain
    [ Sigv4.Provider.Env.make ();
      Sigv4.Provider.Static.make ~access_key:"AKIDEXAMPLE" ~secret_key:"..." () ]
```

The cohttp-eio adapter bundles a ready-made chain (`env` then `ecs`).
The `ecs` provider caches credentials until they near expiry, so pass a clock via `~now`:

```ocaml
let now () = Eio.Time.now clock in
Sigv4_cohttp_eio.run ~now ~client @@ fun () ->
  let credentials = Sigv4.Credentials.fetch () in
  Sigv4.sign ~now ~credentials (* ... *)
```

### Service-specific knobs

```ocaml
(* S3 needs the body-hash header to be signed and disables path normalization. *)
Sigv4.sign
  ~signed_body_header:true
  ~normalize_path:false
  ...
```

| Option | Default | When to enable |
|---|---|---|
| `?signed_body_header:bool` | `false` | S3 (required), Glacier |
| `?normalize_path:bool` | `true` | Set to `false` for S3 |
| `?omit_session_token:bool` | `false` | Some STS-like flows where the token is sent but not signed |
| `?payload:string` | `""` | Request body bytes (used to compute the SHA256) |

## What's not (yet) supported

This library covers header-based SigV4 signing for the common cases (DynamoDB, Lambda, API Gateway, EC2, SQS, SNS, ...). 
The following are intentionally out of scope for the initial release:

- **`UNSIGNED-PAYLOAD` and `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`**.
  S3 streaming uploads and large file uploads where the body hash is computed separately or omitted from the signature. Today `?payload` only accepts the raw body bytes; the literal payload-hash modes will be added later as a variant.
- **Pre-signed URL (query-string signing)**.
  Generating `?X-Amz-Algorithm=...&X-Amz-Signature=...` URLs (typically used for S3 GET/PUT URLs shared with browsers). A separate `Sigv4.presign` entry point will be added when there's demand.
- **SigV4a (asymmetric / multi-region)**.
  Used by S3 Multi-Region Access Points and a few other newer services.

Contributions for any of the above are welcome.

## Dependencies

Core `sigv4` runtime: [`uri`](https://github.com/mirage/ocaml-uri),
[`digestif`](https://github.com/mirage/digestif).

Optional adapter:

- `sigv4-cohttp-eio` — the ECS/container-endpoint provider. Depends on `eio`,
  `cohttp-eio`, `yojson`.

Test-only: `alcotest`, `yojson`.

The core `sigv4` library uses no `Unix`, `Str`, or other platform-specific modules, so it works on bytecode, native, MirageOS, and js_of_ocaml targets.
`sign` is pure. The single function that reads ambient process state is `Sigv4.Provider.Env.make` (via `Sys.getenv_opt`), and it accepts an injectable `?getenv` for testing; everything else in the core performs no I/O. HTTP-based credential resolution lives only in the opt-in `sigv4-cohttp-eio` adapter.

## Testing

The test suite uses fixtures vendored from [awslabs/aws-c-auth][aws-c-auth] (Apache-2.0) via a git submodule. To run:

```sh
git submodule update --init test/aws-c-auth
dune runtest
```

If the submodule is not initialized, the test runner prints a notice and exits 0 (so `opam install --with-test` works in environments without the fixtures).

[aws-c-auth]: https://github.com/awslabs/aws-c-auth

## Acknowledgements

The AWS SigV4 test-suite fixtures under `test/aws-c-auth/` are sourced from [`awslabs/aws-c-auth`](https://github.com/awslabs/aws-c-auth),
licensed under the Apache License 2.0. See that repository for the original attribution and license text.

## License

[MIT](./LICENSE)
