%% Copyright (c) 2024, Travelping GmbH <info@travelping.com>.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(opentelemetry_cowboy_h).
-behavior(cowboy_stream).

%% cowboy_stream callbacks
-export([init/3, data/4, info/3, terminate/3, early_error/5]).

%% API
-export([set_current_span/1]).

-include_lib("kernel/include/logger.hrl").
-include_lib("opentelemetry_api/include/opentelemetry.hrl").
-include_lib("opentelemetry_api/include/otel_tracer.hrl").

-type otel_metrics_callback() :: fun((Attributes :: #{opentelemetry:attribute_key() =>
                                                          opentelemetry:attribute_value()},
                                      ReqDuration :: non_neg_integer(),
                                      ReqBodySize :: integer() | undefined,
                                      RespBodySize :: integer() | undefined,
                                      Opts :: map()
                                     ) -> any()).
-type otel_opts() :: #{metrics_cb => otel_metrics_callback()}.

-export_type([otel_metrics_callback/0]).

-record(state,
        {
         next :: any(),
         opts :: otel_opts(),

         span_ctx :: opentelemetry:span_ctx() | undefined,
         metric_attrs :: #{opentelemetry:attribute_key() => opentelemetry:attribute_value()},
         req_start :: integer() | undefined,
         req_body_size :: non_neg_integer() | undefined,
         resp_status :: cowboy:http_status() | undefined,
         resp_body_size = 0 :: non_neg_integer() | undefined
        }).

-spec set_current_span(cowboy_req:req()) -> opentelemetry:span_ctx() | undefined.
set_current_span(#{'_otel_span_ctx' := SpanCtx}) ->
    ?set_current_span(SpanCtx);
set_current_span(_) ->
    undefined.

-spec init(cowboy_stream:streamid(), cowboy_req:req(), cowboy:opts())
          -> {[{spawn, pid(), timeout()}], #state{}}.
init(StreamID, Req, Opts) ->
    safe(fun() -> init_(StreamID, Req, Opts) end).

init_(StreamID, Req, GunOpts) ->
    Now = erlang:monotonic_time(),
    State = otel_init_req(Now, Req, maps:get(otel_opts, GunOpts, #{})),
    {Commands, Next} = cowboy_stream:init(
                         StreamID, Req#{'_otel_span_ctx' => State#state.span_ctx}, GunOpts),
    {Commands, fold(Commands, State#state{next = Next})}.

-spec data(cowboy_stream:streamid(), cowboy_stream:fin(), cowboy_req:req_body(), State)
          -> {cowboy_stream:commands(), State} when State::#state{}.
data(StreamID, IsFin = fin, Data, State = #state{req_body_size = undefined}) ->
    do_data(StreamID, IsFin, Data, State#state{req_body_size = byte_size(Data)});

data(StreamID, IsFin = fin, Data, State = #state{req_body_size = ReqBodySize}) ->
    do_data(StreamID, IsFin, Data, State#state{req_body_size = ReqBodySize + byte_size(Data)});

data(StreamID, IsFin, Data, State = #state{req_body_size = undefined}) ->
    do_data(StreamID, IsFin, Data, State#state{req_body_size = byte_size(Data)});
data(StreamID, IsFin, Data, State = #state{req_body_size = ReqBodySize}) ->
    do_data(StreamID, IsFin, Data,
            State#state{req_body_size = ReqBodySize + byte_size(Data)}).

do_data(StreamID, IsFin, Data, State0 = #state{next = Next0}) ->
    {Commands, Next} = cowboy_stream:data(StreamID, IsFin, Data, Next0),
    {Commands, fold(Commands, State0#state{next = Next})}.

-spec info(cowboy_stream:streamid(), any(), State)
          -> {cowboy_stream:commands(), State} when State::#state{}.
info(StreamID, Info, State0 = #state{next = Next0}) ->
    {Commands, Next} = cowboy_stream:info(StreamID, Info, Next0),
    {Commands, fold(Commands, State0#state{next = Next})}.

fold([], State) ->
    State;
fold([{spawn, _Pid, _}|Tail], State) ->
    %% TBD: add otel event for the spawn
    fold(Tail, State);
fold([{inform, _Status, _Headers}|Tail], State) ->
    %% TBD: add otel event ?
    fold(Tail, State);
fold([{response, Status, Headers, Body}|Tail], State0) ->
    State = otel_response(Status, Headers, State0),
    fold(Tail, State#state{resp_body_size = resp_body_size(Body)});
fold([{error_response, Status, Headers, Body}|Tail], State = #state{resp_status = undefined}) ->
    %% The error_response command only results in a response
    %% if no response was sent before.
    fold([{response, Status, Headers, Body}|Tail], State);
fold([{error_response, _Status, _Headers, _Body}|Tail], State) ->
    fold(Tail, State);
fold([{headers, Status, Headers}|Tail], State0) ->
    State = otel_response(Status, Headers, State0),
    fold(Tail, State);
fold([{data, _, Data}|Tail], State = #state{resp_body_size = RespBodySize}) ->
    fold(Tail, State#state{resp_body_size = RespBodySize + resp_body_size(Data)});
fold([_|Tail], State) ->
    fold(Tail, State).

-spec terminate(cowboy_stream:streamid(), cowboy_stream:reason(), #state{}) -> any().
terminate(StreamID, Reason, State = #state{next = Next}) ->
    Res = cowboy_stream:terminate(StreamID, Reason, Next),
    otel_terminate(erlang:monotonic_time(), State),
    Res.

-spec early_error(cowboy_stream:streamid(), cowboy_stream:reason(),
                  cowboy_stream:partial_req(), Resp, cowboy:opts()) -> Resp
              when Resp::cowboy_stream:resp_command().
early_error(StreamID, Reason, PartialReq, Resp0, GunOpts) ->
    ReqStart = erlang:monotonic_time(),
    Resp = {response, RespStatus, RespHeaders, RespBody}
        = cowboy_stream:early_error(StreamID, Reason, PartialReq, Resp0, GunOpts),

    State0 = otel_early_error(ReqStart, Reason, PartialReq, maps:get(otel_opts, GunOpts, #{})),
    State = otel_response(RespStatus, RespHeaders, State0),
    otel_terminate(erlang:monotonic_time(), State#state{resp_body_size = resp_body_size(RespBody)}),

    Resp.

resp_body_size({sendfile, _, Len, _}) ->
    Len;
resp_body_size(Data) ->
    iolist_size(Data).

-define(is_recording(SpanCtx), SpanCtx =/= undefined andalso SpanCtx#span_ctx.is_recording =:= true).

otel_start_span(Method, Req, Opts) ->
    SpanName = iolist_to_binary([<<"HTTP ">>, Method]),
    SpanCtx = ?start_span(SpanName, #{kind => ?SPAN_KIND_SERVER}),
    {SpanAttrs, MetricAttrs} =
        case ?is_recording(SpanCtx) orelse is_map_key(metrics_cb, Opts) of
            true ->
                %% only process the attributes when span is recoding or a metrics_cb is set
                otel_req_attrs(Req, Opts);
            _ ->
                {#{}, #{}}
        end,
    otel_span:set_attributes(SpanCtx, SpanAttrs),
    #state{opts = Opts, span_ctx = SpanCtx, metric_attrs = MetricAttrs}.

otel_init_req(ReqStart, #{method := Method, headers := Headers} = Req, Opts) ->
    ?LOG(debug, Req#{ev => ?FUNCTION_NAME}),
    otel_propagator_text_map:extract(maps:to_list(Headers)),
    State = otel_start_span(Method, Req, Opts),
    State#state{req_start = ReqStart}.

otel_response(Status, Headers, State = #state{opts = Opts, span_ctx = SpanCtx,
                                              metric_attrs = MetricAttrs0})
  when ?is_recording(SpanCtx); is_map_key(metrics_cb, Opts) ->
    %% only process the attributes when span is recoding or a metrics_cb is set
    ?LOG(debug, #{ev => ?FUNCTION_NAME, status => Status, headers => Headers}),
    HdrAttrs = maps:fold(fun(K, V, A) -> fmt_hdr(<<"response">>, K, V, A) end, [],Headers),
    Attrs = {[{'http.status_code', Status}],
             [{'http.response.status_code', Status} | HdrAttrs]},
    {SpanAttrs, MetricAttrs} = otel_attrs_filter(Attrs, Opts),
    otel_span:set_attributes(SpanCtx, SpanAttrs),
    case Status of
        Status when Status >= 500 ->
            otel_span:set_status(
              SpanCtx, opentelemetry:status(?OTEL_STATUS_ERROR, status(Status)));
        _ ->
            ok
    end,
    State#state{metric_attrs =  maps:merge(MetricAttrs0, MetricAttrs)};
otel_response(_Status, _Headers, State) ->
    State.

otel_early_error(ReqStart, _Reason, PartialReq, Opts) ->
    ?LOG(debug, #{ev => ?FUNCTION_NAME, reason => _Reason, partial_req => PartialReq}),
    Method = maps:get(method, PartialReq, <<"INVALID METHOD">>),
    Headers = maps:get(headers, PartialReq, #{}),
    otel_propagator_text_map:extract(maps:to_list(Headers)),
    State = otel_start_span(Method, PartialReq, Opts),
    State#state{req_start = ReqStart}.

otel_terminate(Now, State = #state{span_ctx = SpanCtx}) ->
    ?LOG(debug, #{ev => ?FUNCTION_NAME}),
    otel_span:end_span(SpanCtx),
    metrics_cb(Now, State),
    ok.

metrics_cb(Now, #state{opts = #{metrics_cb := Cb} = Opts,
                       metric_attrs = MetricAttrs, req_start = ReqStart,
                       req_body_size = ReqBodySize, resp_body_size = RespBodySize}) ->
    try Cb(MetricAttrs, Now - ReqStart, ReqBodySize, RespBodySize, Opts)
    catch
        Class:Term:Stacktrace ->
            ?LOG(error, "opentelmetry_cowboy_h metrics callback failed with ~0tp:~0tp, Stack: ~0tp",
                 [Class, Term, Stacktrace])
    end,
    ok;
metrics_cb(_Now, _State) ->
    ok.

safe(Fun) ->
    try Fun()
    catch
        C:E:St ->
            ?LOG(error, "opentelmetry_cowboy_h failed with ~0tp:~0tp, Stack: ~0tp",
                 [C, E, St]),
            erlang:raise(C, E, St)
    end.

otel_attrs_filter({A1_13, A1_20}, Opts) ->
    SpanAttrs =
        case Opts of
            #{stability_opt_in := http} -> A1_20;
            #{stability_opt_in := '1.13'} -> A1_13;
            #{stability_opt_in := '1.20'} -> A1_20;
            #{stability_opt_in := dup} -> A1_13 ++ A1_20;
            _ -> A1_20
        end,
    {SpanAttrs, maps:from_list(A1_20)}.

otel_req_attrs(Req, Opts) ->
    Headers = maps:get(headers, Req, #{}),
    HdrAttrs = maps:fold(fun(K, V, A) -> fmt_hdr(<<"request">>, K, V, A) end, [], Headers),
    Init = {[{'net.transport', 'IP.TCP'}],
            [{'network.transport', tcp} | HdrAttrs]},
    Attrs = maps:fold(fun(K, V, Attrs) -> otel_req_attrs(K, V, Req, Attrs) end, Init, Req),
    otel_attrs_filter(Attrs, Opts).

otel_req_attrs(method, Method, _Req, {A1_13, A1_20}) ->
    {[{'http.method', Method} | A1_13],
     [{'http.request.method', Method} | A1_20]};
otel_req_attrs(version, Version, _Req, {A1_13, A1_20}) ->
    {http_flavor(Version, A1_13), network_protocol(Version, A1_20)};
otel_req_attrs(scheme, Scheme, _Req, {A1_13, A1_20}) ->
    {[{'http.scheme', Scheme} | A1_13],
     [{'url.scheme', Scheme} | A1_20]};
otel_req_attrs(host, Host, _Req, {A1_13, A1_20}) ->
    {[{'http.host', Host} | A1_13],
     [{'server.address', Host} | A1_20]};
otel_req_attrs(port, Port, _Req, {A1_13, A1_20}) ->
    {[{'http.host.port', Port} | A1_13],
     [{'server.port', Port} | A1_20]};
otel_req_attrs(path, Path, _Req, {A1_13, A1_20}) ->
    {[{'http.target', Path} | A1_13],
     [{'url.path', Path} | A1_20]};
otel_req_attrs(headers, #{<<"user-agent">> := UserAgent} = _Headers, _Req, {A1_13, A1_20}) ->
    {[{'http.user_agent', UserAgent} | A1_13],
     [{'user_agent.original', UserAgent} | A1_20]};
otel_req_attrs(peer, {RemoteIP, RemotePort}, Req, {A1_13, A1_20}) ->
    Headers = maps:get(headers, Req, #{}),
    ClientIP = client_ip(Headers, RemoteIP),
    PeerIP = iolist_to_binary(inet:ntoa(RemoteIP)),
    {[{'http.client_ip', ClientIP},
      {'net.host.ip', PeerIP} | A1_13],
     [{'client.address', ClientIP},
      {'network.peer.address', PeerIP},
      {'network.peer.port', RemotePort} | A1_20]};
otel_req_attrs(sock, {LocalIP, LocalPort}, _Req, {A1_13, A1_20}) ->
    {A1_13,
     [{'network.local.address', iolist_to_binary(inet:ntoa(LocalIP))},
      {'network.local.port', LocalPort} | A1_20]};
otel_req_attrs(_K, _V, _Req, Attrs) ->
    Attrs.

http_flavor('HTTP/1.0', Attrs) ->
    [{'http.flavor', '1.0'} | Attrs];
http_flavor('HTTP/1.1', Attrs) ->
    [{'http.flavor', '1.1'} | Attrs];
http_flavor('HTTP/2', Attrs) ->
    [{'http.flavor', '2.0'} | Attrs];
http_flavor('SPDY', Attrs) ->
    [{'http.flavor', 'SPDY'} | Attrs];
http_flavor('QUIC', Attrs) ->
    [{'http.flavor', 'QUIC'} | Attrs];
http_flavor(_, Attrs) ->
    Attrs.

network_protocol('HTTP/1.0', Attrs) ->
    [{'network.protocol.name', 'http'},
     {'network.protocol.version', <<"1.0">>} | Attrs];
network_protocol('HTTP/1.1', Attrs) ->
    [{'network.protocol.name', 'http'},
     {'network.protocol.version', <<"1.1">>} | Attrs];
network_protocol('HTTP/2', Attrs) ->
    [{'network.protocol.name', 'http'},
     {'network.protocol.version', <<"2">>} | Attrs];
network_protocol('SPDY', Attrs) ->
    [{'network.protocol.name', 'spdy'} | Attrs];
network_protocol('QUIC', Attrs) ->
    [{'network.protocol.name', 'quic'} | Attrs];
network_protocol(_, Attrs) ->
    Attrs.

client_ip(Headers, RemoteIP) ->
    case maps:get(<<"x-forwarded-for">>, Headers, undefined) of
        undefined ->
            iolist_to_binary(inet:ntoa(RemoteIP));
        Addresses ->
            hd(binary:split(Addresses, <<",">>))
    end.

fmt_hdr(Type, K, V, A) ->
    try
        [{<<"http.", Type/binary, ".header.", K/binary>>, iolist_to_binary(V)} | A]
    catch _:_ ->
            ?LOG(error, "opentelmetry_cowboy_h invalid ~s headers {~0tp:~0tp}", [Type, K, V]),
            A
    end.

-spec status(cowboy:http_status()) -> binary().
status(100) -> <<"100 Continue">>;
status(101) -> <<"101 Switching Protocols">>;
status(102) -> <<"102 Processing">>;
status(103) -> <<"103 Early Hints">>;
status(200) -> <<"200 OK">>;
status(201) -> <<"201 Created">>;
status(202) -> <<"202 Accepted">>;
status(203) -> <<"203 Non-Authoritative Information">>;
status(204) -> <<"204 No Content">>;
status(205) -> <<"205 Reset Content">>;
status(206) -> <<"206 Partial Content">>;
status(207) -> <<"207 Multi-Status">>;
status(208) -> <<"208 Already Reported">>;
status(226) -> <<"226 IM Used">>;
status(300) -> <<"300 Multiple Choices">>;
status(301) -> <<"301 Moved Permanently">>;
status(302) -> <<"302 Found">>;
status(303) -> <<"303 See Other">>;
status(304) -> <<"304 Not Modified">>;
status(305) -> <<"305 Use Proxy">>;
status(306) -> <<"306 Switch Proxy">>;
status(307) -> <<"307 Temporary Redirect">>;
status(308) -> <<"308 Permanent Redirect">>;
status(400) -> <<"400 Bad Request">>;
status(401) -> <<"401 Unauthorized">>;
status(402) -> <<"402 Payment Required">>;
status(403) -> <<"403 Forbidden">>;
status(404) -> <<"404 Not Found">>;
status(405) -> <<"405 Method Not Allowed">>;
status(406) -> <<"406 Not Acceptable">>;
status(407) -> <<"407 Proxy Authentication Required">>;
status(408) -> <<"408 Request Timeout">>;
status(409) -> <<"409 Conflict">>;
status(410) -> <<"410 Gone">>;
status(411) -> <<"411 Length Required">>;
status(412) -> <<"412 Precondition Failed">>;
status(413) -> <<"413 Request Entity Too Large">>;
status(414) -> <<"414 Request-URI Too Long">>;
status(415) -> <<"415 Unsupported Media Type">>;
status(416) -> <<"416 Requested Range Not Satisfiable">>;
status(417) -> <<"417 Expectation Failed">>;
status(418) -> <<"418 I'm a teapot">>;
status(421) -> <<"421 Misdirected Request">>;
status(422) -> <<"422 Unprocessable Entity">>;
status(423) -> <<"423 Locked">>;
status(424) -> <<"424 Failed Dependency">>;
status(425) -> <<"425 Unordered Collection">>;
status(426) -> <<"426 Upgrade Required">>;
status(428) -> <<"428 Precondition Required">>;
status(429) -> <<"429 Too Many Requests">>;
status(431) -> <<"431 Request Header Fields Too Large">>;
status(451) -> <<"451 Unavailable For Legal Reasons">>;
status(500) -> <<"500 Internal Server Error">>;
status(501) -> <<"501 Not Implemented">>;
status(502) -> <<"502 Bad Gateway">>;
status(503) -> <<"503 Service Unavailable">>;
status(504) -> <<"504 Gateway Timeout">>;
status(505) -> <<"505 HTTP Version Not Supported">>;
status(506) -> <<"506 Variant Also Negotiates">>;
status(507) -> <<"507 Insufficient Storage">>;
status(508) -> <<"508 Loop Detected">>;
status(510) -> <<"510 Not Extended">>;
status(511) -> <<"511 Network Authentication Required">>;
status(_) -> <<"">>.
