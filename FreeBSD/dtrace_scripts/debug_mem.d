#!/usr/sbin/dtrace -s

ebpf-buffers:malloc { @["ebpf malloc"] = count(); trace(arg0) }
ebpf-buffers:free { @["ebpf free"] = count(); trace(arg0) }

ebpf_obj_new:entry { @["ebpf_obj_new"] = count(); trace(arg0) }
ebpf_obj_delete:entry { @["ebpf_obj_delete"] = count(); trace(arg0) }
