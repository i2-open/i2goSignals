<!-- gosignals-brand-hero -->
<picture><source media="(prefers-color-scheme: dark)" srcset="../../brand/logo/gosignals-hero-primary.svg"><img src="../../brand/logo/gosignals-hero-on-light.svg" alt="goSignals" height="77"></picture>

# 47. Latency histograms carry no stream label

Date: 2026-10-04

## Status

Accepted (community; #352).

## Context

#352 adds two transmitter-side latency histograms, queue time and
acknowledgement time (see `CONTEXT.md`). Per-stream counters such as
`goSignals_router_events_in_total` already carry `stream_id`, so the
obvious move is to label the histograms the same way.

A histogram is one series per bucket. With about 14 buckets, a `stream_id`
label on two histograms costs about 28 series per stream on every node that
has owned the stream: 1,000 streams is about 28,000 series for two metrics.
A counter or gauge costs one series per stream.

Alternatives considered: `stream_id` on every histogram, matching the
counters; and `stream_id` behind an opt-in setting.

## Decision

A latency histogram is labelled by transfer method (`tfr`: PUSH, POLL,
SSTP) and by nothing that grows with the number of streams. SSTP is not
split by role.

Per-stream signals are gauges or counters, one series per stream. For
"how far behind is stream X" that is the backlog pair,
`goSignals_router_stream_backlog_depth` and
`goSignals_router_stream_backlog_oldest_age_seconds`.

The opt-in setting was rejected: it gives two shapes of the same metric to
document, dashboard and test, for a question the backlog gauges already
answer.

This is the rule for future latency histograms, not only #352's.

## Consequences

- The histograms answer "is PUSH, POLL or SSTP delivery slow on this
  node", never "which stream is slow". An operator finds the stream from
  the oldest-pending-age gauge.
- A per-stream latency distribution is not available from metrics. If one
  is ever needed, it is a deliberate amendment to this ADR, not a label
  added in passing.
- Series count for latency metrics is fixed per node, whatever the stream
  count.
