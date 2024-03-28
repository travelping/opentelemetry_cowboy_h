opentelemetry_cowboy_h
=====

[OpenTelemetry][OpenTelemetry] instrumentation for the [Cowboy][Cowboy] HTTP server.

This package contains a [`cowboy_stream`][CowboyStream`] handler that will instrument each request and
create OpenTelemetry spans.

## Usage

Configure your cowboy server with the `cowboy_opentelemetry_h` stream handler first.

```erlang
cowboy:start_clear(http, [{port, Port}], #{
    env => #{dispatch => Dispatch},
    stream_handlers => [opentelemetry_cowboy_h, cowboy_stream_h]
}.
```

Cowboy spans the actual request handler in a new process. To attach that process to the span
create by the stream handler, add `opentelemetry_cowboy_h:set_current_span(Req)` to the init
method of the handler.

```Erlang
init(Req, State) ->
    opentelemetry_cowboy_h:set_current_span(Req),
    {ok, Req, State}.
```

<!-- Links -->
[OpenTelemetry]: https://github.com/open-telemetry/opentelemetry-erlang
[Cowboy]: https://github.com/ninenines/cowboy
[CowboyStream]: https://ninenines.eu/docs/en/cowboy/2.12/manual/cowboy_stream/
