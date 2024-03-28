opentelemetry\_cowboy\_experimental\_h
=====

[OpenTelemetry][OpenTelemetry] metrics callback for the [Cowboy][Cowboy] HTTP servers.

This package provides a metrics callback implementation for the [`opentelemetry_cowboy_h`][OpenTelemetryH`] handler that will record metrics for each request.

## Usage

Initialize the metrics and configure your cowboy server with the `cowboy_opentelemetry_h`
stream handler and a `metric_cb` setting in `otel_opts`.

```erlang
opentelemetry_cowboy_experimental_h:init(),
cowboy:start_clear(http, [{port, Port}], #{
    env => #{dispatch => Dispatch},
    otel_opts => #{metrics_cb => fun opentelemetry_cowboy_experimental_h:metrics_cb/5},
    stream_handlers => [opentelemetry_cowboy_h, cowboy_stream_h]
}.
```

<!-- Links -->
[OpenTelemetry]: https://github.com/open-telemetry/opentelemetry-erlang
[Cowboy]: https://github.com/ninenines/cowboy
[OpenTelemetryH]: hhttps://github.com/travelping/opentelemetry_cowboy_h
