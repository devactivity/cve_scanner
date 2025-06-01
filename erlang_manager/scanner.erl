-module(scanner).
-export([start/2, scan_target/2, execute_scan/3]).

start(Targets, Protocols) ->
  io:format("Starting scan with protocols: ~p~n", [Protocols]),
  [begin
     Pid = spawn(?MODULE, scan_target, [Target, Protocols]),
     register(list_to_atom("scanner_" ++ Target), Pid)
   end || Target <- Targets],
  loop(length(Targets)).

loop(0) ->
  io:format("All scans completed~n"),
  init:stop();
loop(Remaining) ->
  receive
    {result, Target, Data} ->
      io:format("Received data for ~s: ~p~n", [Target, Data]),
      loop(Remaining - 1)
  after 10000 ->
    io:format("Scan timeout~n"),
    init:stop()
  end.

scan_target(Target, Protocols) ->
  Ports = case lists:member("udp", Protocols) of
      true -> [53, 67, 68];
      false -> [22, 80, 443]
  end,
  Results = [execute_scan(Target, Port, Proto) || Port <- Ports, Proto <- Protocols],
  self() ! {result, Target, Results},
  ok.

execute_scan(Target, Port, Proto) ->
  Cmd = lists:concat(["../rust_core/target/release/rust_core ", Target, " ", Port, " ", Proto]),
  Output = os:cmd(Cmd),
  case string:prefix(Output, "{\"port\":") of
    nomatch ->
      {Port, Proto, closed, []};
    _ ->
      {struct, Json} = mochijson2:decode(Output),
      Banner = proplists:get_value(<<"banner">>, Json, <<"">>),

      % run vulnerability check through haskell
      VulnCmd = lists:concat(["../haskell_analyzer/analyzer'", binary_to_list(Banner), "'"]),
      VulnOutput = os:cmd(VulnCmd),

      CVEs = string:tokens(VulnOutput, "\n"),
      {Port, Proto, open, CVEs}
  end.

