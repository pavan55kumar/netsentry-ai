"""NetSentry AI — Phase 8: Comprehensive Operational Performance Benchmarking.

Measures and records empirical operational benchmarks on the current system:
1. System hardware, OS, and Python environment metadata.
2. Model artifact loading latency and memory footprint.
3. CSV ingestion and validation latency across varying dataset sizes.
4. Per-flow single-record inference latency (mean, median, p95, p99).
5. High-throughput batch inference latency and measured flow processing rate.
6. Offline PCAP packet ingestion and 5-tuple flow reconstruction throughput.
7. Safe failure and non-finite quarantine overhead.

Outputs machine-readable metrics to `artifacts/phase8_performance_results.json`.
"""
from __future__ import annotations

import gc
import json
import os
import platform
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn

# Add src to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "src"))

from netsentry.data.loader import load_csv, validate_schema
from netsentry.data.synthetic import make_demo_dataset
from netsentry.pcap.flow_extractor import extract_flows_from_pcap
from netsentry.predict import score_flows


def get_system_metadata() -> dict[str, Any]:
    """Capture authentic environment and hardware architecture details."""
    cpu_count = os.cpu_count() or 1
    mem_info = "Unknown"
    try:
        import psutil
        total_ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        mem_info = f"{total_ram_gb} GB"
    except ImportError:
        pass

    return {
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count_logical": cpu_count,
        "total_ram": mem_info,
        "python_version": sys.version.split()[0],
        "python_executable": sys.executable,
        "scikit_learn_version": sklearn.__version__,
        "pandas_version": pd.__version__,
        "numpy_version": np.__version__,
        "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def benchmark_model_loading(model_path: Path, iterations: int = 20) -> dict[str, Any]:
    """Measure deserialization latency and model size on disk."""
    if not model_path.is_file():
        return {"status": "SKIPPED", "reason": f"File {model_path} not found"}

    file_size_bytes = model_path.stat().st_size
    latencies = []
    
    for _ in range(iterations):
        gc.collect()
        t0 = time.perf_counter()
        _ = joblib.load(model_path)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)  # Convert to ms

    return {
        "model_file": str(model_path.name),
        "file_size_bytes": file_size_bytes,
        "file_size_kb": round(file_size_bytes / 1024, 2),
        "file_size_mb": round(file_size_bytes / (1024 * 1024), 3),
        "iterations": iterations,
        "mean_load_time_ms": round(float(np.mean(latencies)), 3),
        "std_load_time_ms": round(float(np.std(latencies)), 3),
        "min_load_time_ms": round(float(np.min(latencies)), 3),
        "max_load_time_ms": round(float(np.max(latencies)), 3),
    }


def benchmark_csv_ingestion(sizes: list[int]) -> list[dict[str, Any]]:
    """Measure CSV parsing and schema validation latency across dataset scales."""
    results = []
    for n in sizes:
        df = make_demo_dataset(rows=n, random_state=42)
        temp_csv = WORKSPACE_ROOT / f".local-temp/bench_{n}.csv"
        temp_csv.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(temp_csv, index=False)

        try:
            # Measure CSV load time
            t0 = time.perf_counter()
            loaded_df = load_csv(temp_csv)
            t_load = (time.perf_counter() - t0) * 1000.0

            # Measure schema validation time
            t0 = time.perf_counter()
            val_report = validate_schema(loaded_df, label_column="label")
            t_val = (time.perf_counter() - t0) * 1000.0

            mem_usage_kb = round(loaded_df.memory_usage(deep=True).sum() / 1024.0, 2)

            results.append({
                "n_samples": n,
                "n_columns": len(loaded_df.columns),
                "csv_file_size_kb": round(temp_csv.stat().st_size / 1024.0, 2),
                "in_memory_dataframe_kb": mem_usage_kb,
                "load_duration_ms": round(t_load, 3),
                "schema_validation_duration_ms": round(t_val, 3),
                "total_ingest_and_validate_ms": round(t_load + t_val, 3),
                "throughput_flows_per_second": round(n / ((t_load + t_val) / 1000.0), 1),
            })
        finally:
            if temp_csv.is_file():
                temp_csv.unlink()

    return results


def benchmark_inference_latency(
    model: Any,
    features: list[str],
    single_iterations: int = 500,
    batch_iterations: int = 50,
) -> dict[str, Any]:
    """Measure single-flow real-time latency and high-throughput batch scoring."""
    # Synthesize test rows matching schema
    test_batch_1000 = make_demo_dataset(rows=1000, random_state=123)
    single_row = test_batch_1000.iloc[:1].copy()

    # Warmup
    for _ in range(10):
        _ = score_flows(model, features, single_row)

    # 1. Single-flow latency (Real-time online inspection)
    single_latencies = []
    for _ in range(single_iterations):
        t0 = time.perf_counter()
        _ = score_flows(model, features, single_row)
        t1 = time.perf_counter()
        single_latencies.append((t1 - t0) * 1000.0)

    # 2. Batch throughput (Offline / TAP aggregation)
    batch_sizes = [100, 500, 1000]
    batch_results = {}

    for b_size in batch_sizes:
        batch_df = make_demo_dataset(rows=b_size, random_state=777)
        b_times = []
        for _ in range(batch_iterations):
            t0 = time.perf_counter()
            _ = score_flows(model, features, batch_df)
            t1 = time.perf_counter()
            b_times.append((t1 - t0) * 1000.0)

        mean_batch_ms = float(np.mean(b_times))
        flows_per_sec = (b_size / (mean_batch_ms / 1000.0))
        batch_results[f"batch_{b_size}"] = {
            "batch_size": b_size,
            "mean_batch_time_ms": round(mean_batch_ms, 3),
            "p95_batch_time_ms": round(float(np.percentile(b_times, 95)), 3),
            "throughput_flows_per_second": round(flows_per_sec, 1),
        }

    return {
        "single_flow_latency_ms": {
            "iterations": single_iterations,
            "mean": round(float(np.mean(single_latencies)), 4),
            "std": round(float(np.std(single_latencies)), 4),
            "median": round(float(np.median(single_latencies)), 4),
            "p95": round(float(np.percentile(single_latencies, 95)), 4),
            "p99": round(float(np.percentile(single_latencies, 99)), 4),
            "min": round(float(np.min(single_latencies)), 4),
            "max": round(float(np.max(single_latencies)), 4),
        },
        "batch_inference_throughput": batch_results,
    }


def benchmark_pcap_extraction(pcap_path: Path, iterations: int = 5) -> dict[str, Any]:
    """Measure Scapy packet reading and 5-tuple flow aggregation performance."""
    if not pcap_path.is_file():
        return {"status": "SKIPPED", "reason": f"PCAP {pcap_path} not found"}

    file_size_bytes = pcap_path.stat().st_size
    extract_times = []
    pcap_res = None

    for _ in range(iterations):
        t0 = time.perf_counter()
        pcap_res = extract_flows_from_pcap(pcap_path)
        t1 = time.perf_counter()
        extract_times.append((t1 - t0) * 1000.0)

    total_packets = pcap_res.total_packets_read if pcap_res else 0
    total_flows = pcap_res.total_flows_extracted if pcap_res else 0
    mean_ms = float(np.mean(extract_times))
    packets_per_sec = (total_packets / (mean_ms / 1000.0)) if mean_ms > 0 else 0.0

    return {
        "pcap_file": str(pcap_path.name),
        "file_size_bytes": file_size_bytes,
        "total_packets_read": total_packets,
        "total_flows_extracted": total_flows,
        "iterations": iterations,
        "mean_parse_duration_ms": round(mean_ms, 3),
        "min_parse_duration_ms": round(float(np.min(extract_times)), 3),
        "max_parse_duration_ms": round(float(np.max(extract_times)), 3),
        "packets_per_second": round(packets_per_sec, 1),
        "disclaimer": "Scapy operates in user-space Python and is suitable for offline PCAP forensics; live line-rate 10G/100G requires kernel-bypass NIC drivers (DPDK/AF_PACKET) and hardware meters.",
    }


def benchmark_safe_failure_overhead(model: Any, features: list[str]) -> dict[str, Any]:
    """Measure computational overhead of non-finite inspection and quarantine."""
    clean_batch = make_demo_dataset(rows=500, random_state=42)
    corrupt_batch = clean_batch.copy()
    corrupt_batch[features] = corrupt_batch[features].astype(float)
    # Inject 5% non-finite infinities into first feature
    corrupt_batch.loc[corrupt_batch.index[::20], features[0]] = np.inf

    # Measure clean scoring
    t0 = time.perf_counter()
    _ = score_flows(model, features, clean_batch, quarantine_non_finite=True)
    t_clean = (time.perf_counter() - t0) * 1000.0

    # Measure corrupt scoring with quarantine policy
    t0 = time.perf_counter()
    res_corrupt = score_flows(model, features, corrupt_batch, quarantine_non_finite=True)
    t_corrupt = (time.perf_counter() - t0) * 1000.0

    quarantined_count = int((res_corrupt["prediction"] == -1).sum())

    return {
        "batch_size": 500,
        "clean_scoring_duration_ms": round(t_clean, 3),
        "quarantine_scoring_duration_ms": round(t_corrupt, 3),
        "quarantined_flows_count": quarantined_count,
        "overhead_pct": round(((t_corrupt - t_clean) / max(t_clean, 0.001)) * 100.0, 2),
    }


def main():
    print("=" * 70)
    print("NetSentry AI — Phase 8 Operational Performance Benchmarking")
    print("=" * 70)

    tracemalloc.start()
    t_start = time.perf_counter()

    sys_meta = get_system_metadata()
    print(f"Platform: {sys_meta['os_name']} {sys_meta['os_release']} ({sys_meta['machine']})")
    print(f"Python: {sys_meta['python_version']} | CPUs: {sys_meta['cpu_count_logical']} | RAM: {sys_meta['total_ram']}")

    # 1. Model Loading
    model_path = WORKSPACE_ROOT / "artifacts/best_model.joblib"
    features_path = WORKSPACE_ROOT / "artifacts/feature_names.json"
    print("\n1. Benchmarking Model Artifact Deserialization...")
    loading_res = benchmark_model_loading(model_path)
    print(f"   Model Size: {loading_res.get('file_size_kb', 0)} KB | Mean Load Latency: {loading_res.get('mean_load_time_ms', 0)} ms")

    # Load model for subsequent tests
    model = joblib.load(model_path)
    features = json.loads(features_path.read_text(encoding="utf-8"))

    # 2. CSV Ingestion
    print("\n2. Benchmarking CSV Ingestion & Schema Validation...")
    csv_res = benchmark_csv_ingestion([500, 1000, 5000])
    for c in csv_res:
        print(f"   {c['n_samples']:,} flows: {c['load_duration_ms']} ms load, {c['schema_validation_duration_ms']} ms val -> {c['throughput_flows_per_second']:,} flows/sec")

    # 3. Model Inference Latency & Throughput
    print("\n3. Benchmarking Model Inference Latency & Batch Throughput...")
    infer_res = benchmark_inference_latency(model, features)
    s_lat = infer_res["single_flow_latency_ms"]
    print(f"   Single-Flow Real-Time: Mean = {s_lat['mean']} ms, Median = {s_lat['median']} ms, p95 = {s_lat['p95']} ms, p99 = {s_lat['p99']} ms")
    for b_key, b_val in infer_res["batch_inference_throughput"].items():
        print(f"   Batch {b_val['batch_size']}: {b_val['mean_batch_time_ms']} ms -> {b_val['throughput_flows_per_second']:,} flows/sec throughput")

    # 4. PCAP Extraction
    print("\n4. Benchmarking Offline PCAP Parsing...")
    pcap_path = WORKSPACE_ROOT / "data/sample/test_traffic.pcap"
    pcap_res = benchmark_pcap_extraction(pcap_path)
    print(f"   Parsed {pcap_res.get('total_packets_read', 0)} packets -> {pcap_res.get('total_flows_extracted', 0)} flows in {pcap_res.get('mean_parse_duration_ms', 0)} ms ({pcap_res.get('packets_per_second', 0)} pkts/sec)")

    # 5. Safe Failure Overhead
    print("\n5. Benchmarking Non-Finite Safe Failure & Quarantine Overhead...")
    sf_overhead = benchmark_safe_failure_overhead(model, features)
    print(f"   Clean: {sf_overhead['clean_scoring_duration_ms']} ms vs Quarantined: {sf_overhead['quarantine_scoring_duration_ms']} ms (Quarantined {sf_overhead['quarantined_flows_count']} flows)")

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_bench_duration = round(time.perf_counter() - t_start, 2)

    final_results = {
        "benchmark_metadata": {
            "version": "Phase 8.0 Final",
            "total_benchmark_duration_seconds": total_bench_duration,
            "peak_memory_mb": round(peak_mem / (1024 * 1024), 2),
        },
        "system_environment": sys_meta,
        "model_loading_benchmark": loading_res,
        "csv_ingestion_benchmark": csv_res,
        "inference_latency_benchmark": infer_res,
        "pcap_extraction_benchmark": pcap_res,
        "safe_failure_overhead_benchmark": sf_overhead,
    }

    output_file = WORKSPACE_ROOT / "artifacts/phase8_performance_results.json"
    output_file.write_text(json.dumps(final_results, indent=2), encoding="utf-8")
    print(f"\nSaved machine-readable performance results to: {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
