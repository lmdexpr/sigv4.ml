(** AWS Signature Version 4 (header-based signing).

    {!sign} is a pure function: the caller injects time, credentials, and the request to be signed,
    and no I/O is performed. Credential acquisition is decoupled from signing through
    {!Credentials.handler} / {!Credentials.fetch}, so callers that cache or refresh credentials can
    do so without coupling that logic to the signing call. *)

(** Credentials used to sign requests. The type is abstract and there is no public constructor:
    instances can only be obtained by calling {!fetch} from within the dynamic extent of a
    {!handler}, which means [secret_access_key] and [session_token] cannot leak through ordinary
    printing, logging, or pattern matching from outside this library. *)
module Credentials : sig
  type t

  val handler :
    callback:
      (provide:(access_key:string -> secret_key:string -> ?session_token:string -> unit -> t) -> t) ->
    (unit -> 'a) ->
    'a
  (** Register a credentials provider for the dynamic extent of the continuation.

      [callback] is invoked each time {!fetch} is called within that extent, and it must yield
      credentials by calling [provide] with the appropriate labeled arguments. Implementations may
      cache, refresh, or read from a remote provider. *)

  val fetch : unit -> t
  (** Resolve credentials via the currently-active {!handler}. Raises [Effect.Unhandled] if no
      handler is installed on the call stack. *)
end

exception No_credentials of string
(** Raised by {!with_provider} (at the {!Credentials.fetch} site) when every provider declines. *)

module Provider = Provider

val with_provider : Provider.t -> (unit -> 'a) -> 'a
(** Install [provider] for the dynamic extent of the continuation; {!Credentials.fetch} resolves
    through it, raising {!No_credentials} if it declines. *)

val sign :
  now:(unit -> float) ->
  credentials:Credentials.t ->
  region:string ->
  service:string ->
  http_method:string ->
  ?payload:string ->
  ?signed_body_header:bool ->
  ?normalize_path:bool ->
  ?omit_session_token:bool ->
  uri:Uri.t ->
  (string * string) list ->
  (string * string) list
(** Compute the headers required to authenticate an AWS request via SigV4. Pure function: no I/O, no
    effects.

    Returns only the headers that should be {b added} to the request:
    - [Authorization]
    - [X-Amz-Date]
    - [X-Amz-Content-Sha256] (only when [~signed_body_header:true])
    - [X-Amz-Security-Token] (only when the resolved credentials carry a session token)

    The caller is responsible for merging these into the actual request.

    @param now Unix epoch seconds (UTC).
    @param http_method Uppercase HTTP method (e.g. ["GET"], ["POST"]).
    @param payload
      Request body bytes used to compute the payload hash. Defaults to the empty string.
    @param signed_body_header
      When [true], the [X-Amz-Content-Sha256] header is added to the request and signed. Required by
      S3; optional elsewhere. Defaults to [false] (matches the AWS C-Auth reference implementation).
    @param normalize_path
      When [true] (the default), the URI path is normalized per RFC 3986 §5.2.4 (resolve [.] / [..]
      and collapse consecutive [/]) before signing. Set to [false] for S3, which signs the path
      verbatim.
    @param omit_session_token
      When [true], [X-Amz-Security-Token] is still included in the returned headers (so it is sent
      on the request) but is excluded from the signed headers and signature. Used by certain
      STS-like flows. Defaults to [false].
    @param uri
      Full request URI. Path and query are part of the signature. The [Host] header value used in
      the canonical request is derived from this URI; the default port (443 for https, 80 for http)
      is stripped to match what HTTP clients put on the wire.
    @param headers
      Existing request headers (positional argument). All entries are signed (names are compared
      case-insensitively; values are trimmed). Any caller-supplied [Host] header is ignored — the
      signed value is always derived from [~uri]. *)
