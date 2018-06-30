# Generic eBPF benchmarks

We did some micro benchmarks to measure the performance
of generic-ebpf. Below shows their setup and results.

## Map performance benchmark

June 30th 2018: Since our hash table map implementation was wrong, we deleted previous benchmark
results from this repository. When this message added to this document.

Here we have performance number of maps. Benchmark procedure is based on [tommyds's
one](http://www.tommyds.it/doc/benchmark). Please see our code at benchmark/map\_benchmark.c
for more details.

We compared Linux's native map and generic-ebpf (with ebpf-dev) map on FreeBSD/Linux for each benchmark types.

### Setup

- CPU: Intel(R) Core(TM) i7-6850K CPU @ 3.60GHz (3599.03-MHz K8-class CPU)
- Memory: 4GB
- OS: Linux-4.16.10 (Ubuntu 18.04-LTS) and FreeBSD 12.0-CUREENT (revision: 334876)
- Turn off Hyper-Threading and Turbo-Boost
- Run benchmark on single CPU (set affinity by taskset or cpuset)
- On FreeBSD, turn off all of the debug features of kernel (BUF\_TRACKING, DDB, FULL\_BUF\_TRACKING, GDB, DEADLKRES, INVARIANTS, INVARIANT\_SUPPORT, WITNESS, WITNESS\_SKIPSPIN, MALLOC\_DEBUG\_MAXZONES)
- Turn off KPTI for both kernels

<!---
### Results

#### Hashtable Map

Below shows benchmark results for hashtable map. Lower is better.

##### Insert
![Insert](plots/hashtable_map_bench_insert.png "Hashtable insert")

##### Change
![Change](plots/hashtable_map_bench_change.png "Hashtable change")

##### Hit
![Hit](plots/hashtable_map_bench_hit.png "Hashtable hit")

##### Miss
![Miss](plots/hashtable_map_bench_miss.png "Hashtable miss")

##### Remove
![Remove](plots/hashtable_map_bench_remove.png "Hashtable remove")
-->
