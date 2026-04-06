from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class HardwareProfile:
    cpu_cores: int
    ram_gb: float
    gpu_name: str | None
    vram_gb: float
    has_cuda: bool
    has_metal: bool
    has_rocm: bool


def _read_meminfo_bytes() -> int:
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                parts = line.split()
                return int(parts[1]) * 1024
    if platform.system() == "Darwin":
        output = subprocess.check_output(
            ["sysctl", "-n", "hw.memsize"],
            text=True,
        ).strip()
        return int(output)
    return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))


def _detect_vram() -> tuple[str | None, float, bool, bool]:
    if shutil.which("nvidia-smi") is not None:
        output = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
            text=True,
        ).strip()
        first = output.splitlines()[0]
        name, memory_mb = [item.strip() for item in first.split(",", maxsplit=1)]
        return name, round(float(memory_mb) / 1024, 2), True, False
    if shutil.which("rocm-smi") is not None:
        output = subprocess.check_output(["rocm-smi", "--showproductname", "--showmeminfo", "vram"], text=True)
        match = re.search(r"GPU\[[0-9]+\]\s+:?\s+(.+)", output)
        name = match.group(1).strip() if match else "AMD GPU"
        return name, 8.0, False, True
    return None, 0.0, False, False


def detect_hardware() -> HardwareProfile:
    gpu_name, vram_gb, has_cuda, has_rocm = _detect_vram()
    ram_gb = round(_read_meminfo_bytes() / (1024**3), 2)
    return HardwareProfile(
        cpu_cores=os.cpu_count() or 1,
        ram_gb=ram_gb,
        gpu_name=gpu_name,
        vram_gb=vram_gb,
        has_cuda=has_cuda,
        has_metal=platform.system() == "Darwin" and platform.machine() == "arm64",
        has_rocm=has_rocm,
    )


def recommend_config(hw: HardwareProfile) -> dict[str, int | str | bool]:
    if hw.vram_gb >= 16 and hw.ram_gb >= 30:
        variant = "gemma-3-27b-it"
    elif hw.vram_gb >= 7.5 and hw.ram_gb >= 13:
        variant = "gemma-3-12b-it"
    elif hw.vram_gb >= 2.5 and hw.ram_gb >= 4.5:
        variant = "gemma-3-4b-it"
    else:
        variant = "gemma-3-1b-it"
    pool_size = 1 if hw.vram_gb <= 4 else min(4, max(1, int(hw.vram_gb // 2.5)))
    return {
        "gemma_variant": variant,
        "n_gpu_layers": -1 if (hw.has_cuda or hw.has_metal or hw.has_rocm) else 0,
        "n_threads": max(1, hw.cpu_cores),
        "gemma_pool_size": pool_size,
        "context_length": 8192 if hw.ram_gb < 16 else 16384,
        "use_mlock": hw.ram_gb >= 8,
    }

