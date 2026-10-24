#!/usr/bin/env bash
set -e

# Always run from the project root directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BUILD_TYPE="Debug"

CMAKE_BIN="cmake"
if [ -x /usr/bin/cmake ]; then
  CMAKE_BIN="/usr/bin/cmake"
fi

# Parse optional arguments
for arg in "$@"; do
  case $arg in
    --release|-r)
      BUILD_TYPE="Release"
      ;;
    --clean|-c)
      echo "🧹 Cleaning build directory..."
      rm -rf build
      ;;
    --help|-h)
      echo "Usage: ./build.sh [options]"
      echo "Options:"
      echo "  --release, -r    Build with Release mode (-O3)"
      echo "  --clean,   -c    Remove build directory before building"
      echo "  --help,    -h    Show this help message"
      exit 0
      ;;
  esac
done

echo "🔧 Configuring project (${BUILD_TYPE})..."
"$CMAKE_BIN" -B build -DCMAKE_BUILD_TYPE="${BUILD_TYPE}"

echo "🚀 Compiling with all available cores..."
"$CMAKE_BIN" --build build -j

echo "✅ Build completed successfully!"
echo "   - Library:       build/aethon/libaethon_lib.a"
echo "   - Benchmark:     build/benchmarks/aethon_benchmark"
echo "   - AF_XDP Engine: build/src/afxdp_control"

