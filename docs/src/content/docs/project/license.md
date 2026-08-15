---
title: License
description: MIT.
---

gspwn is released under the MIT License.

```
MIT License

Copyright (c) 2026 indspl0it

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The canonical copy is [`LICENSE`](https://github.com/Indspl0it/gspwn/blob/main/LICENSE)
in the repository.

## Third-party components

gspwn clones the projects below at provision time. Each carries its own licence,
and none is vendored into this repository.

| Project | Role |
|---|---|
| syzkaller | The Track K fuzzer |
| AFL++ | The Track U fuzzer, through its container image |
| LLVM libFuzzer | Track U C harnesses |
| Linux | The instrumented kernel under test |
| `open-gpu-kernel-modules` | The Track K target |
| `libnvidia-container`, `nvidia-container-toolkit` | The Track U targets |
| `kdump-tools`, `pstore-tools`, `mokutil` | Crash capture and Secure Boot state |

The documentation site is built with Astro Starlight and renders diagrams with
Mermaid, both under their own licences.

## Use

The licence permits use of gspwn. It grants no authorisation to test a system
the operator does not own. See
[Rules of engagement](/gspwn/project/rules-of-engagement/).
