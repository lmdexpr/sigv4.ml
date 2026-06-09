let test_one
  Aws_suite_fixtures.
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
    } =
  Alcotest.test_case name `Quick @@ fun () ->
  let actual =
    Sigv4.Credentials.handler ~callback:(fun ~provide ->
      provide ~access_key ~secret_key ?session_token ())
    @@ fun () ->
    let credentials = Sigv4.Credentials.fetch () in
    Sigv4.sign ~now:(Fun.const epoch) ~credentials ~region ~service ~http_method ~payload:body
      ~signed_body_header ~normalize_path ~omit_session_token ~uri headers
  in
  Alcotest.(check string)
    name
    (List.assoc "Authorization" expected)
    (List.assoc "Authorization" actual)

let fixtures_dir = "aws-c-auth/tests/aws-signing-test-suite/v4"

let () =
  if not @@ Sys.file_exists fixtures_dir then begin
    print_endline "aws-c-auth submodule is not initialized; skipping AWS SigV4 suite.";
    exit 0
  end

let () =
  Alcotest.run "aws-sigv4-suite"
    [ "v4-header", Aws_suite_fixtures.all fixtures_dir |> List.map test_one ]
