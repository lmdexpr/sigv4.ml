(** Loader for the vendored AWS SigV4 v4 test-suite fixtures.

    Each fixture directory contains:
    - [context.json]: credentials, region, service, timestamp, flags
    - [request.txt]: a "rough" HTTP/1.1 request
    - [header-signature.txt]: the expected hex signature

    This module is responsible only for I/O and input parsing. The actual call to {!Sigv4.sign} and
    the assertion live in [test_aws_suite.ml]. *)

type t = {
  name : string;
  access_key : string;
  secret_key : string;
  session_token : string option;
  region : string;
  service : string;
  epoch : float;
  http_method : string;
  uri : Uri.t;
  headers : (string * string) list;
  body : string;
  signed_body_header : bool;
  normalize_path : bool;
  omit_session_token : bool;
  expected : (string * string) list;
}

let read_file path =
  let ic = open_in_bin path in
  let n = in_channel_length ic in
  let s = really_input_string ic n in
  close_in ic;
  s

let strip_cr s =
  let n = String.length s in
  if n > 0 && s.[n - 1] = '\r' then String.sub s 0 (n - 1) else s

(* Parse a "rough" HTTP/1.1 request used by the AWS test suite. *)
let parse_request raw =
  let n = String.length raw in
  let nl1 =
    match String.index_opt raw '\n' with Some i -> i | None -> failwith "no request line"
  in
  let request_line = strip_cr (String.sub raw 0 nl1) in
  (* "METHOD <target> HTTP/x.y" — target may contain literal spaces. *)
  let http_method, request_target =
    match String.index_opt request_line ' ' with
    | None -> failwith ("malformed request line: " ^ request_line)
    | Some first ->
      let last = String.rindex request_line ' ' in
      let m = String.sub request_line 0 first in
      let t = String.sub request_line (first + 1) (last - first - 1) in
      m, t
  in
  let headers = ref [] in
  let i = ref (nl1 + 1) in
  let body_start = ref n in
  let continue = ref true in
  while !continue && !i < n do
    let nl = match String.index_from_opt raw !i '\n' with Some j -> j | None -> n in
    let line = strip_cr (String.sub raw !i (nl - !i)) in
    if line = "" then begin
      body_start := nl + 1;
      continue := false
    end
    else begin
      if line.[0] = ' ' || line.[0] = '\t' then
        begin match
          !headers
        with
        | (k, v) :: rest -> headers := (k, v ^ " " ^ String.trim line) :: rest
        | [] -> failwith "obs-fold without preceding header"
      end
      else
        begin match
          String.index_opt line ':'
        with
        | None -> failwith ("bad header line: " ^ line)
        | Some j ->
          let k = String.sub line 0 j in
          let v = String.sub line (j + 1) (String.length line - j - 1) in
          headers := (k, String.trim v) :: !headers
      end;
      i := nl + 1
    end
  done;
  let body = if !body_start >= n then "" else String.sub raw !body_start (n - !body_start) in
  let headers = List.rev !headers in
  let host =
    match List.find_opt (fun (k, _) -> String.lowercase_ascii k = "host") headers with
    | Some (_, v) -> v
    | None -> failwith "missing Host header"
  in
  let uri = Uri.of_string ("https://" ^ host ^ request_target) in
  http_method, uri, headers, body

(* Parse "YYYY-MM-DDTHH:MM:SSZ" into a Unix epoch second value (UTC). *)
let epoch_of_iso8601 s =
  Scanf.sscanf s "%4d-%2d-%2dT%2d:%2d:%2dZ" (fun y m d hh mm ss ->
    let y' = if m <= 2 then y - 1 else y in
    let era = (if y' >= 0 then y' else y' - 399) / 400 in
    let yoe = y' - (era * 400) in
    let doy = (((153 * (m + if m > 2 then -3 else 9)) + 2) / 5) + d - 1 in
    let doe = (yoe * 365) + (yoe / 4) - (yoe / 100) + doy in
    let days = (era * 146097) + doe - 719468 in
    float_of_int ((days * 86400) + (hh * 3600) + (mm * 60) + ss))

let json_string ctx field = Yojson.Safe.Util.(ctx |> member field |> to_string)

let json_string_opt ctx field =
  match Yojson.Safe.Util.member field ctx with
  | `Null -> None
  | `String s -> Some s
  | _ -> failwith ("non-string for " ^ field)

let json_bool_opt ctx field =
  match Yojson.Safe.Util.member field ctx with
  | `Null -> None
  | `Bool b -> Some b
  | _ -> failwith ("non-bool for " ^ field)

let load fixtures_dir name =
  let dir = Filename.concat fixtures_dir name in
  let ctx = Yojson.Safe.from_file (Filename.concat dir "context.json") in
  let creds = Yojson.Safe.Util.member "credentials" ctx in
  let access_key = json_string creds "access_key_id" in
  let secret_key = json_string creds "secret_access_key" in
  let session_token = json_string_opt creds "token" in
  let http_method, uri, headers, body =
    parse_request (read_file (Filename.concat dir "request.txt"))
  in
  let region = json_string ctx "region" in
  let service = json_string ctx "service" in
  let epoch = epoch_of_iso8601 (json_string ctx "timestamp") in
  let signed_body_header = json_bool_opt ctx "sign_body" |> Option.value ~default:false in
  let normalize_path = json_bool_opt ctx "normalize" |> Option.value ~default:true in
  let omit_session_token = json_bool_opt ctx "omit_session_token" |> Option.value ~default:false in
  let _, _, expected, _ =
    parse_request (read_file (Filename.concat dir "header-signed-request.txt"))
  in
  {
    name;
    access_key;
    secret_key;
    session_token;
    region;
    service;
    epoch;
    http_method;
    uri;
    headers;
    body;
    signed_body_header;
    normalize_path;
    omit_session_token;
    expected;
  }

let all fixtures_dir =
  Sys.readdir fixtures_dir |> Array.to_list
  |> List.filter (fun n -> Sys.is_directory (Filename.concat fixtures_dir n))
  |> List.sort String.compare
  |> List.map (load fixtures_dir)
