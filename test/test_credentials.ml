(* Tests for the credential Provider abstraction, the env provider, and the chain combinator.
   No Unix is needed: the env provider's [getenv] is injected with a pure stub. *)

(* --- small string helpers (avoid pulling in Str) --- *)

let index_of haystack needle =
  let n = String.length haystack and m = String.length needle in
  let rec go i =
    if i + m > n then None else if String.sub haystack i m = needle then Some i else go (i + 1)
  in
  go 0

let contains haystack needle = Option.is_some (index_of haystack needle)

(* Extract the access key from an "Authorization: AWS4-HMAC-SHA256 Credential=<AK>/<scope...>" header. *)
let access_key_of signed =
  let auth = List.assoc "Authorization" signed in
  let marker = "Credential=" in
  match index_of auth marker with
  | None -> Alcotest.failf "no Credential= in %S" auth
  | Some i ->
    let start = i + String.length marker in
    let stop = String.index_from auth start '/' in
    String.sub auth start (stop - start)

(* Resolve [provider] and sign a trivial request, returning the headers to add. *)
let sign_with provider =
  Sigv4.with_provider provider @@ fun () ->
  let credentials = Sigv4.Credentials.fetch () in
  Sigv4.sign
    ~now:(fun () -> 0.)
    ~credentials ~region:"us-east-1" ~service:"s3" ~http_method:"GET"
    ~uri:(Uri.of_string "https://example.com/")
    []

let expect_no_credentials ~contains:subs f =
  match f () with
  | exception Sigv4.No_credentials msg ->
    List.iter
      (fun sub ->
        Alcotest.(check bool) (Printf.sprintf "message contains %S" sub) true (contains msg sub))
      subs
  | _ -> Alcotest.fail "expected Sigv4.No_credentials to be raised"

(* --- env provider --- *)

let test_env_present () =
  let getenv = function
    | "AWS_ACCESS_KEY_ID" -> Some "AKID_ENV"
    | "AWS_SECRET_ACCESS_KEY" -> Some "secret"
    | _ -> None
  in
  Alcotest.(check string)
    "env access key" "AKID_ENV"
    (access_key_of (sign_with (Sigv4.Provider.Env.make ~getenv ())))

let test_env_session_token () =
  let getenv = function
    | "AWS_ACCESS_KEY_ID" -> Some "AKID"
    | "AWS_SECRET_ACCESS_KEY" -> Some "secret"
    | "AWS_SESSION_TOKEN" -> Some "TOKEN123"
    | _ -> None
  in
  let signed = sign_with (Sigv4.Provider.Env.make ~getenv ()) in
  Alcotest.(check string)
    "session token header" "TOKEN123"
    (List.assoc "X-Amz-Security-Token" signed)

let test_env_missing () =
  let getenv _ = None in
  expect_no_credentials ~contains:[ "[env]" ] (fun () ->
    ignore (sign_with (Sigv4.Provider.Env.make ~getenv ())))

(* --- chain --- *)

let decline name = Sigv4.Provider.v ~name (fun () -> Result.error "not applicable")

let test_chain_first_wins () =
  let p =
    Sigv4.Provider.chain
      [
        Sigv4.Provider.Static.make ~access_key:"AK1" ~secret_key:"s" ();
        Sigv4.Provider.Static.make ~access_key:"AK2" ~secret_key:"s" ();
      ]
  in
  Alcotest.(check string) "first resolver wins" "AK1" (access_key_of (sign_with p))

let test_chain_skips_decline () =
  let p =
    Sigv4.Provider.chain
      [ decline "a"; Sigv4.Provider.Static.make ~access_key:"AK2" ~secret_key:"s" () ]
  in
  Alcotest.(check string) "declines are skipped" "AK2" (access_key_of (sign_with p))

let test_chain_all_decline () =
  let p = Sigv4.Provider.chain [ decline "alpha"; decline "beta" ] in
  expect_no_credentials ~contains:[ "[alpha]"; "[beta]" ] (fun () -> ignore (sign_with p))

let () =
  Alcotest.run "credentials"
    [
      ( "provider",
        [
          Alcotest.test_case "env present resolves" `Quick test_env_present;
          Alcotest.test_case "env session token is signed" `Quick test_env_session_token;
          Alcotest.test_case "env missing declines" `Quick test_env_missing;
          Alcotest.test_case "chain first resolver wins" `Quick test_chain_first_wins;
          Alcotest.test_case "chain skips declines" `Quick test_chain_skips_decline;
          Alcotest.test_case "chain all decline raises" `Quick test_chain_all_decline;
        ] );
    ]
