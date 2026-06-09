(** Cohttp-eio adapter for [Sigv4]. *)

module Ecs : sig
  val make : now:(unit -> float) -> client:Cohttp_eio.Client.t -> Sigv4.Provider.t
  (** Credentials from the AWS container endpoint ([AWS_CONTAINER_CREDENTIALS_RELATIVE_URI] /
      [_FULL_URI]). Caches the result until it nears the reported expiry, using [now] (e.g.
      [fun () -> Eio.Time.now clock]); declines when neither variable is set. Build once and reuse
      so the cache is shared. *)
end

val run : now:(unit -> float) -> client:Cohttp_eio.Client.t -> (unit -> 'a) -> 'a
(** Installs the default chain ([Env] then {!Ecs}); raises {!Sigv4.No_credentials} if none resolve.
*)
