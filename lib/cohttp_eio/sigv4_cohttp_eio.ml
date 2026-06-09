(** Cohttp-eio adapter for [Sigv4]. *)

module Ecs = struct
  let ecs_endpoint_host = "169.254.170.2"

  (* Refresh this many seconds before the reported expiry. *)
  let refresh_margin = 300.

  (* RELATIVE_URI (joined with the link-local host) takes precedence over FULL_URI. *)
  let endpoint_url () =
    match Sys.getenv_opt "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" with
    | Some path -> Some (Printf.sprintf "http://%s%s" ecs_endpoint_host path)
    | None -> Sys.getenv_opt "AWS_CONTAINER_CREDENTIALS_FULL_URI"

  (* "YYYY-MM-DDThh:mm:ssZ" -> Unix-epoch seconds; None on any unexpected shape. *)
  let epoch_of_iso8601 s =
    try
      Some
        (Scanf.sscanf s "%4d-%2d-%2dT%2d:%2d:%2d" (fun y m d hh mm ss ->
           let y = if m <= 2 then y - 1 else y in
           let era = (if y >= 0 then y else y - 399) / 400 in
           let yoe = y - (era * 400) in
           let doy = (((153 * (m + if m > 2 then -3 else 9)) + 2) / 5) + d - 1 in
           let doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy in
           let days = (era * 146097) + doe - 719468 in
           float_of_int ((days * 86400) + (hh * 3600) + (mm * 60) + ss)))
    with Scanf.Scan_failure _ | End_of_file -> None

  let from_endpoint ~client ~url =
    let open Yojson.Safe.Util in
    let json =
      Eio.Switch.run @@ fun sw ->
      let _, body = Cohttp_eio.Client.call ~sw client `GET (Uri.of_string url) in
      Eio.Buf_read.of_flow ~max_size:10_000 body |> Eio.Buf_read.take_all |> Yojson.Safe.from_string
    in
    let access_key = json |> member "AccessKeyId" |> to_string in
    let secret_key = json |> member "SecretAccessKey" |> to_string in
    let session_token = match member "Token" json with `String s -> Some s | _ -> None in
    let expiry =
      match member "Expiration" json with `String s -> epoch_of_iso8601 s | _ -> None
    in
    (~access_key, ~secret_key, ~session_token), expiry

  (* Reuse the cached credentials until they near [expiry]; re-fetch otherwise. The cache is a
     private ref captured per provider, so build the provider once and reuse it. *)
  let make ~now ~client =
    let cache = ref None in
    Sigv4.Provider.v ~name:"ecs" @@ fun () ->
    let still_fresh =
      match !cache with
      | Some (creds, Some expiry) when now () +. refresh_margin < expiry -> Some creds
      | _ -> None
    in
    match still_fresh with
    | Some creds -> Ok creds
    | None -> (
      match endpoint_url () with
      | None -> Result.error "no AWS_CONTAINER_CREDENTIALS_* variable set"
      | Some url ->
        let creds, expiry = from_endpoint ~client ~url in
        cache := Some (creds, expiry);
        Ok creds)
end

(** Installs the default chain ([Env] then [Ecs]). *)
let run ~now ~client =
  Sigv4.with_provider @@ Sigv4.Provider.chain [ Sigv4.Provider.Env.make (); Ecs.make ~now ~client ]
