#!/bin/bash -eu
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CASCAVEL — ClusterFuzzLite Build Script                            ║
# ║  Product of RET Tecnologia (rettecnologia.org)                      ║
# ╚══════════════════════════════════════════════════════════════════════╝

# Install project dependencies
pip3 install -r requirements.txt
pip3 install atheris

# Build fuzz targets
compile_python_fuzzer tests/fuzz_sanitizer.py \
    --add-data "plugins:plugins" \
    --add-data "wordlists:wordlists"
