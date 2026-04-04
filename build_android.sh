#!/usr/bin/env bash
# build_android.sh — Build fialka-core as .so for Android via cargo-ndk
#
# Prerequisites:
#   cargo install cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#   ANDROID_NDK_HOME must point to your NDK (e.g. ~/Android/Sdk/ndk/27.x.x)
#
# Output: target/aarch64-linux-android/release/libfialka_core.so
#         target/armv7-linux-androideabi/release/libfialka_core.so
#         target/x86_64-linux-android/release/libfialka_core.so

set -e

cargo ndk \
  -t arm64-v8a \
  -t armeabi-v7a \
  -t x86_64 \
  -o ./jniLibs \
  build --release

echo "Build complete. .so files in ./jniLibs/"
