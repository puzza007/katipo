#!/usr/bin/env python3
"""Write the hand-made seed inputs for each fuzz target into fuzz/corpus/.

Seeds are generated rather than committed so their encoding always matches
what the targets parse. Run from anywhere: python3 fuzz/seeds/make_seeds.py
"""

import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "..", "corpus")


def lines(*ls):
    return b"".join(struct.pack(">H", len(l)) + l for l in ls)


HEADER_SEEDS = {
    "simple": lines(
        b"HTTP/1.1 200 OK\r\n",
        b"Content-Type: text/plain\r\n",
        b"Content-Length: 5\r\n",
        b"\r\n",
    ),
    "continue": lines(
        b"HTTP/1.1 100 Continue\r\n",
        b"\r\n",
        b"HTTP/1.1 200 OK\r\n",
        b"X: y\r\n",
        b"\r\n",
    ),
    "early_hints": lines(
        b"HTTP/1.1 103 Early Hints\r\n",
        b"Link: </a>\r\n",
        b"\r\n",
        b"HTTP/1.1 204 No Content\r\n",
        b"\r\n",
    ),
    "redirect": lines(
        b"HTTP/1.1 302 Found\r\n",
        b"Location: /b\r\n",
        b"\r\n",
        b"HTTP/1.1 200 OK\r\n",
        b"A: 1\r\n",
        b"\r\n",
    ),
    "trailers": lines(
        b"HTTP/1.1 200 OK\r\n",
        b"Transfer-Encoding: chunked\r\n",
        b"\r\n",
        b"Trailer-One: x\r\n",
        b"\r\n",
    ),
    "h2": lines(b"HTTP/2 200 \r\n", b"content-type: a\r\n", b"\r\n"),
    "ncsa": lines(b"HTTP 200 OK\r\n", b"Server: old\r\n", b"\r\n"),
    "bare_cr": lines(b"HTTP/1.1 200 OK\r\n", b"X: a\rb\r\n", b"Y: c\x00d\n", b"\r\n"),
    "folded": lines(b"HTTP/1.1 200 OK\r\n", b"X: a\r\n", b" b\r\n", b"\r\n"),
    "no_status": lines(b"X: a\r\n", b"\r\n", b"Y: b\r\n"),
}

# The other targets start from an empty corpus, which libFuzzer still
# needs to exist.
SEEDS = {
    "fuzz_headers": HEADER_SEEDS,
    "fuzz_request": {},
    "fuzz_framing": {},
    "fuzz_transfer": {},
}


def main():
    for target, seeds in SEEDS.items():
        d = os.path.join(CORPUS, target)
        os.makedirs(d, exist_ok=True)
        for name, data in seeds.items():
            with open(os.path.join(d, "seed_" + name), "wb") as f:
                f.write(data)
        print(f"{target}: {len(seeds)} seeds")


if __name__ == "__main__":
    main()
