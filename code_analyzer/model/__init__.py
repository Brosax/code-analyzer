"""The model layer: the only code that opens a socket to a model.

``client`` speaks the wire protocols (OpenAI-compatible ``/v1`` SSE and
Ollama's native ``/api/chat`` NDJSON), ``egress`` decides whether a request may
leave for a given host at all, ``record`` keeps the exact bytes as evidence,
``broker`` arbitrates the single GPU between the conversation and background
jobs, and ``probe`` measures what the configured model can actually do.
"""
