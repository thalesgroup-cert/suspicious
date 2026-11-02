"""Test-only worker entry (`python -m tests.train_probe_worker <workdir>`), started through the
real training_job.popen_launcher in place of inference_server.training_worker. It applies the
real worker's setup, reports what the child sees into <workdir>/probe.json, starts a grandchild
and sleeps, so tests can check the environment, thread pools, process group and orphan exit."""
import json
import os
import subprocess
import sys
import time

from inference_server import training_worker


def main():
    workdir = sys.argv[1]
    threads = int(os.environ["AI_TRAIN_THREADS"])
    training_worker.setup(threads, int(os.environ.get("AI_TRAIN_MAX_MEMORY_MB") or 0))
    params = training_worker.read_params(sys.stdin.buffer)
    import torch
    from threadpoolctl import threadpool_info
    pools = [p["num_threads"] for p in threadpool_info()]
    with training_worker.thread_limits(threads):
        pools_in_run = [p["num_threads"] for p in threadpool_info()]
    grandchild = subprocess.Popen(["sleep", "600"])
    report = {"environ": open("/proc/self/environ", "rb").read().decode(errors="replace"),
              "argv": sys.argv, "params": params, "interop": torch.get_num_interop_threads(),
              "torch_threads": torch.get_num_threads(), "pools": pools,
              "pools_in_run": pools_in_run, "grandchild": grandchild.pid}
    tmp = os.path.join(workdir, ".probe.tmp")
    with open(tmp, "w") as fh:
        json.dump(report, fh)
    os.replace(tmp, os.path.join(workdir, "probe.json"))
    time.sleep(600)


if __name__ == "__main__":
    main()
