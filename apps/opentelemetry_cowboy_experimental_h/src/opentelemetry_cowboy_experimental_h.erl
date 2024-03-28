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

-module(opentelemetry_cowboy_experimental_h).

%% API
-export([init/0, metrics_cb/5]).

-include_lib("kernel/include/logger.hrl").
-include_lib("opentelemetry_api/include/opentelemetry.hrl").
-include_lib("opentelemetry_api/include/otel_tracer.hrl").
-include_lib("opentelemetry_api_experimental/include/otel_meter.hrl").

init() ->
    ?create_histogram('http.server.request.duration',
                      #{description => <<"Duration of HTTP server requests.">>,
                        unit => s}),
    ?create_histogram('http.server.request.body.size',
                      #{description => <<"Size of HTTP server request bodies.">>,
                        unit => 'By'}),
    ?create_histogram('http.server.response.body.size',
                      #{description => <<"Size of HTTP server response bodies.">>,
                        unit => 'By'}),
    ok.

-spec metrics_cb(Attributes :: #{opentelemetry:attribute_key() =>
                                     opentelemetry:attribute_value()},
                 ReqDuration :: non_neg_integer(),
                 ReqBodySize :: integer() | undefined,
                 RespBodySize :: integer() | undefined,
                 Opts :: map()
                ) -> ok.

metrics_cb(Attributes, ReqDuration, ReqBodySize, RespBodySize, _Opts) ->
    MetricAttrs =
        maps:with(['http.request.method', 'url.scheme', 'error.type',
                   'http.response.status_code', 'http.route',
                   'network.protocol.name', 'network.protocol.version',
                   'server.address', 'server.port'], Attributes),
    SecDiv = erlang:convert_time_unit(1, second, native),

    ?histogram_record('http.server.request.duration', ReqDuration / SecDiv, MetricAttrs),
    case is_number(ReqBodySize) of
        true -> ?histogram_record('http.server.request.body.size', ReqBodySize, MetricAttrs);
        false -> ok
    end,
    ?histogram_record('http.server.response.body.size', RespBodySize, MetricAttrs),
    ok.
