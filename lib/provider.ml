(* A provider yields the raw credential fields ([Ok]) or a decline reason ([Error]).
   It never builds a [Sigv4.Credentials.t]; [Sigv4] does the wrapping. *)

type t = {
  name : string option;
  run : unit -> (access_key:string * secret_key:string * session_token:string option, string) result;
}

let v ?name run = { name; run }

let label name reason =
  match name with Some n -> Printf.sprintf "[%s] %s" n reason | None -> reason

let run p = p.run () |> Result.map_error (label p.name)

let chain providers =
  v @@ fun () ->
  let rec go acc = function
    | [] -> (
      Result.error
      @@
      match List.rev acc with
      | [] -> "empty provider chain"
      | reasons -> "no provider resolved credentials: " ^ String.concat "; " reasons)
    | p :: rest ->
      p.run () |> Result.fold ~ok:Result.ok ~error:(fun r -> go (label p.name r :: acc) rest)
  in
  go [] providers

module Static = struct
  let make ~access_key ~secret_key ?session_token () =
    v ~name:"static" @@ fun () -> Result.ok (~access_key, ~secret_key, ~session_token)
end

module Env = struct
  let var_access_key = "AWS_ACCESS_KEY_ID"
  let var_secret_key = "AWS_SECRET_ACCESS_KEY"
  let var_session_token = "AWS_SESSION_TOKEN"

  let make ?(getenv = Sys.getenv_opt) () =
    let resolved =
      match getenv var_access_key, getenv var_secret_key with
      | Some access_key, Some secret_key ->
        Result.ok (~access_key, ~secret_key, ~session_token:(getenv var_session_token))
      | _ ->
        Result.error @@ Printf.sprintf "%s and %s must both be set" var_access_key var_secret_key
    in
    v ~name:"env" @@ fun () -> resolved
end
