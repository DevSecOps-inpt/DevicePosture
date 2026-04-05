# Spark Tuning Notes

## Core checks
- Partition count and skew handling.
- Shuffle volume and stage-level hotspots.
- Broadcast eligibility and join strategy.
- Executor memory/core sizing and GC pressure.
- Serialization format and caching strategy.

## Validation pattern
1. Capture baseline runtime metrics.
2. Apply one tuning change at a time.
3. Measure before/after under comparable workload.
4. Keep improvements that are stable and repeatable.

