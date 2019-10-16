# try_cloudflare_quiche

## Requirements

- CMake 3.0 or newer
- Go 1.11 or newer
- Rust 1.38.0 or newer

## Build

```
git clone https://github.com/nus/quiche_libuv_sample.git
cd quiche_libuv_sample/
git submodule update --init --recursive

mkdir build
cd build
cmake ..
make
cp ../third_party/quiche/examples/cert.key ./
cp ../third_party/quiche/examples/cert.crt ./
```

## Run

Server side terminal.

```
./server
```

Client side terminal.

```
./client
```

## License

```
Copyright (C) 2019 Yota Ichino

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
