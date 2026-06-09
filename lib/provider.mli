(** Credential providers behind {!Sigv4.Provider}. A provider yields the raw credential fields
    ([Ok]) or a decline reason ([Error]); it never builds a [Sigv4.Credentials.t]. *)

type t

val v :
  ?name:string ->
  (unit -> (access_key:string * secret_key:string * session_token:string option, string) result) ->
  t
(** A provider from a thunk. [?name] prefixes its decline reason in {!chain} aggregation. *)

val run : t -> (access_key:string * secret_key:string * session_token:string option, string) result
(** Run a provider, prefixing its decline reason with its name. *)

val chain : t list -> t
(** First provider to resolve wins; if all decline, their reasons are aggregated. *)

(** Fixed credentials. *)
module Static : sig
  val make : access_key:string -> secret_key:string -> ?session_token:string -> unit -> t
end

(** Reads [AWS_ACCESS_KEY_ID] / [AWS_SECRET_ACCESS_KEY] (+ optional [AWS_SESSION_TOKEN]). [?getenv]
    defaults to [Sys.getenv_opt]. *)
module Env : sig
  val make : ?getenv:(string -> string option) -> unit -> t
end
