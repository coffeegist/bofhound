#!/usr/bin/env python3
"""Benchmark script to measure bofhound performance."""
import time
import sys
import subprocess
import json
from pathlib import Path

def run_benchmark(input_path, output_dir, iterations=3):
    """Run bofhound and measure execution time."""
    times = []

    for i in range(iterations):
        print(f"Run {i+1}/{iterations}...")
        start = time.time()

        result = subprocess.run(
            ["poetry", "run", "bofhound", "-i", input_path, "-o", output_dir, "-q"],
            capture_output=True,
            text=True
        )

        elapsed = time.time() - start
        times.append(elapsed)

        if result.returncode != 0:
            print(f"Error: {result.stderr}")
            sys.exit(1)

    avg = sum(times) / len(times)
    min_time = min(times)
    max_time = max(times)

    return {
        "times": times,
        "avg": avg,
        "min": min_time,
        "max": max_time
    }

if __name__ == "__main__":
    input_path = "tests/test_data/ldapsearchpy_logs/ldapsearch_20220413.log"
    output_dir = "garbage/benchmark"

    print(f"Benchmarking: {input_path}")
    print("-" * 50)

    results = run_benchmark(input_path, output_dir)

    print(f"\nResults:")
    print(f"  Average: {results['avg']:.2f}s")
    print(f"  Min:     {results['min']:.2f}s")
    print(f"  Max:     {results['max']:.2f}s")
    print(f"  Times:   {[f'{t:.2f}s' for t in results['times']]}")
