module SHA256 = Digestif.SHA256

let sprintf = Printf.sprintf

module Credentials = struct
  type t = { access_key : string; secret_key : string; session_token : string option }
  type _ Effect.t += Fetch : t Effect.t

  let handler ~callback k =
    try k ()
    with effect Fetch, k ->
      let creds : t =
        callback ~provide:(fun ~access_key ~secret_key ?session_token () ->
          { access_key; secret_key; session_token })
      in
      Effect.Deep.continue k creds

  let fetch () = Effect.perform Fetch
end

exception No_credentials of string

module Provider = Provider

let with_provider provider k =
  let open Effect.Deep in
  try k ()
  with effect Credentials.Fetch, k ->
    begin match Provider.run provider with
    | Ok (~access_key, ~secret_key, ~session_token) ->
      continue k Credentials.{ access_key; secret_key; session_token }
    | Error reason -> discontinue k @@ No_credentials reason
    end

(* civil_from_days *)
let utc_of_epoch t =
  let total = int_of_float (Float.floor t) in
  let days = total / 86400 and rem = total mod 86400 in
  let hh = rem / 3600 and mm = rem / 60 mod 60 and ss = rem mod 60 in
  let z = days + 719468 in
  let era = (if z >= 0 then z else z - 146096) / 146097 in
  let doe = z - (era * 146097) in
  let yoe = (doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365 in
  let y = yoe + (era * 400) in
  let doy = doe - ((365 * yoe) + (yoe / 4) - (yoe / 100)) in
  let mp = ((5 * doy) + 2) / 153 in
  let d = doy - (((153 * mp) + 2) / 5) + 1 in
  let m = mp + if mp < 10 then 3 else -9 in
  let y = if m <= 2 then y + 1 else y in
  y, m, d, hh, mm, ss

let yyyymmdd t =
  let y, m, d, _, _, _ = utc_of_epoch t in
  sprintf "%04d%02d%02d" y m d

let yyyymmddThhmmssZ t =
  let y, m, d, h, mn, s = utc_of_epoch t in
  sprintf "%04d%02d%02dT%02d%02d%02dZ" y m d h mn s

(** Apply RFC 3986 §5.2.4 "remove_dot_segments" plus collapsing of empty segments. Trailing slash is
    preserved. *)
let normalize_path_segments path =
  let last = if String.length path > 0 && path.[String.length path - 1] = '/' then "/" else "" in
  let path =
    String.split_on_char '/' path
    |> List.filter (fun s -> s <> "")
    |> ListLabels.fold_left ~init:[] ~f:(fun acc -> function
      | "." -> acc
      | ".." -> List.drop 1 acc
      | seg -> seg :: acc)
    |> List.rev
  in
  if path = [] then
    "/"
  else
    "/" ^ String.concat "/" path ^ last

(** Drop the port when it is the default for the scheme (443 for https, 80 for http). AWS does this
    when reconstructing the canonical request from the wire Host header on the server side; the AWS
    Java/Python SDKs do the same on the client side. Without this, strictly-validating services such
    as Bedrock Runtime return SignatureDoesNotMatch when the caller's URI carries an explicit
    default port. *)
let drop_default_port uri =
  match Uri.scheme uri, Uri.port uri with
  | Some "https", Some 443 | Some "http", Some 80 -> Uri.with_port uri None
  | _ -> uri

(** Derive the value of the [Host] header from the URI per RFC 9112 §3.2.1, after stripping the
    default port for the scheme. We always source [Host] from the URI rather than from
    caller-supplied headers, so the signing input cannot diverge from what an HTTP client would
    actually put on the wire. *)
let host_header_from_uri uri =
  let uri = drop_default_port uri in
  let host = Uri.host_with_default ~default:"" uri in
  match Uri.port uri with None -> host | Some p -> sprintf "%s:%d" host p

let make_canonical_request ?(normalize_path = true) ~http_method ~uri ~headers ~hashed_payload () =
  let path = Uri.path uri in
  let path = if not normalize_path then path else normalize_path_segments path in
  (* Decode then re-encode each segment so the result is encoded exactly once, regardless of whether the caller's URI contained a literal space or a pre-encoded "%20". *)
  let path = if path = "" then "/" else path in
  let canonical_uri =
    String.split_on_char '/' path
    |> List.map (fun s -> Uri.pct_decode s |> Uri.pct_encode ~component:`Generic)
    |> String.concat "/"
  in
  let canonical_query =
    (* AWS sorts by encoded key; [Uri.encoded_of_query] handles the actual encoding and "k=v&..." formatting. Coerce [] -> [""] so "?foo" becomes "foo=" rather than "foo". *)
    Uri.query uri
    |> List.map (fun (k, vs) -> k, if vs = [] then [ "" ] else vs)
    |> List.sort (fun (a, _) (b, _) ->
      compare (Uri.pct_encode ~component:`Query_key a) (Uri.pct_encode ~component:`Query_key b))
    |> Uri.encoded_of_query
  in
  (* Per AWS canonical request rules: trim header values and collapse runs of internal whitespace to a single space. For duplicate header names, values
     are concatenated by ',' in request order; the joined groups are then sorted by name. *)
  let collapse_whitespace s =
    s
    |> String.map (fun c -> if c = '\t' then ' ' else c)
    |> String.split_on_char ' '
    |> List.filter (fun s -> s <> "")
    |> String.concat " "
  in
  let headers =
    headers
    |> List.map (fun (k, v) -> String.lowercase_ascii k, collapse_whitespace v)
    |> List.stable_sort (fun (a, _) (b, _) -> String.compare a b)
    |> ListLabels.fold_left ~init:[] ~f:(fun acc (k, v) ->
      match acc with
      | (k', vs) :: rest when k = k' -> (k', vs ^ "," ^ v) :: rest
      | _ -> (k, v) :: acc)
    |> List.rev
  in
  let canonical_headers =
    headers |> List.map (fun (k, v) -> sprintf "%s:%s\n" k v) |> String.concat ""
  in
  let signed_headers = headers |> List.map fst |> String.concat ";" in
  ( signed_headers,
    sprintf "%s\n%s\n%s\n%s\n%s\n%s" http_method canonical_uri canonical_query canonical_headers
      signed_headers hashed_payload )

let credential_scope ~region ~service now =
  sprintf "%s/%s/%s/aws4_request" (yyyymmdd now) region service

let signing_key ~secret_key ~region ~service now =
  let hmac_raw ~key s = s |> SHA256.hmac_string ~key |> SHA256.to_raw_string in
  let key = "AWS4" ^ secret_key in
  let key = hmac_raw ~key (yyyymmdd now) in
  let key = hmac_raw ~key region in
  let key = hmac_raw ~key service in
  hmac_raw ~key "aws4_request"

module Option = struct
  include Option

  let prepend option list = Option.fold ~none:list ~some:(fun x -> x :: list) option
  let when_ bool x = if bool then Some x else None
  let unless bool opt = if bool then None else opt
end

let sign ~now ~credentials ~region ~service ~http_method ?(payload = "")
  ?(signed_body_header = false) ?(normalize_path = true) ?(omit_session_token = false) ~uri headers
    =
  let now = now () in
  let Credentials.{ access_key; secret_key; session_token } = credentials in

  let hashed_payload = payload |> SHA256.digest_string |> SHA256.to_hex in

  let date = "X-Amz-Date", yyyymmddThhmmssZ now in
  let content_sha = Option.when_ signed_body_header ("X-Amz-Content-Sha256", hashed_payload) in
  let token = Option.map (fun t -> "X-Amz-Security-Token", t) session_token in

  (* Always derive [Host] from the URI so the signing input matches the actual wire value.
     Any caller-supplied [Host] is dropped. HTTP header names are case-insensitive (RFC 9110
     §5.1), so we filter by lowercased key rather than using [List.remove_assoc]. *)
  let host = "Host", host_header_from_uri uri in
  let headers = List.filter (fun (k, _) -> String.lowercase_ascii k <> "host") headers in

  (* Headers that contribute to the signature. When [omit_session_token] is set, the security token is sent but not signed. *)
  let headers =
    host
    :: (headers
       @ ([ date ] |> Option.prepend content_sha
         |> Option.prepend (Option.unless omit_session_token token)))
  in

  (* The 6 steps below follow
     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html *)

  (* 1. Create a canonical request *)
  let signed_headers, canonical_request =
    make_canonical_request ~normalize_path ~http_method ~uri ~headers ~hashed_payload ()
  in

  (* 2. Create a hash of the canonical request *)
  let hashed_canonical_request = canonical_request |> SHA256.digest_string |> SHA256.to_hex in

  (* 3. Create a string to sign *)
  let string_to_sign =
    sprintf "AWS4-HMAC-SHA256\n%s\n%s\n%s" (yyyymmddThhmmssZ now)
      (credential_scope ~region ~service now)
      hashed_canonical_request
  in

  (* 4. Derive a signing key *)
  let key = signing_key ~secret_key ~region ~service now in

  (* 5. Calculate the signature *)
  let signature = string_to_sign |> SHA256.hmac_string ~key |> SHA256.to_hex in

  (* 6. Add the signature to the HTTP request *)
  let authorization =
    ( "Authorization",
      sprintf "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" access_key
        (credential_scope ~region ~service now)
        signed_headers signature )
  in
  authorization :: ([ date ] |> Option.prepend content_sha |> Option.prepend token)
