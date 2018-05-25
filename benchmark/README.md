# Generic eBPF benchmarks

We did some micro benchmarks to measure the performance
of generic-ebpf. Below shows their setup and results.

## Map performance benchmark

Here we have performance number of maps. Benchmark procedure is based on [tommyds's
one](http://www.tommyds.it/doc/benchmark). Please see our code at benchmark/map\_benchmark.c
for more details.

We compared Linux's native map and generic-ebpf (with ebpf-dev) map on FreeBSD for each benchmark types.
We measured performance for 3 map implementation and for each of them, we measured with/without KPTI(Kernel
Page Table Isolation), because Linux's bpf(2) or our ebpf\_dev calls systemcall for each map operation
(update/delete/lookup) and this is very systemcall-heavy workload. We were interested in how it affects
performance.

### Setup

- CPU: Intel(R) Core(TM) i7-6850K CPU @ 3.60GHz (3599.03-MHz K8-class CPU)
- Memory: 4GB
- OS: Linux-4.16.10 and FreeBSD-11.1-RELEASE
- Turn off Hyper-Threading and Turbo-Boost
- Run benchmark on single CPU (set affinity by taskset or cpuset)

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
