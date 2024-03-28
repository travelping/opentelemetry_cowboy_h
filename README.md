opentelemetry\_cowboy\_h
=====

[OpenTelemetry][OpenTelemetry] instrumentation for the [Cowboy][Cowboy] HTTP server.

The project consists of the two Erlang applications, opentelemetry\_cowboy\_h provides an
Cowboy handler that add OpenTelemetry tracing to incomming requests and the
opentelemetry\_cowboy\_experimental\_h that provides a Cowboy handler that also includes
OpenTelemetry metrics.

See the applications READMEs for details on how to use the handlers.

<!-- Links -->
[OpenTelemetry]: https://github.com/open-telemetry/opentelemetry-erlang
[Cowboy]: https://github.com/ninenines/cowboy
