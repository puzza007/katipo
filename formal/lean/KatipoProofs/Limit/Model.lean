/-!
# `max_body_size`: transcription of `body_too_large` in `c_src/katipo.c`

```c
static int body_too_large(ConnInfo *conn, size_t realsize) {
  curl_off_t length;

  if (conn->body_size == 0 && !conn->encoded &&
      curl_easy_getinfo(conn->easy, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &length) == CURLE_OK &&
      length > conn->max_body_size) {
    return 1;
  }
  conn->body_size += (curl_off_t)realsize;
  return conn->body_size > conn->max_body_size;
}
```

`write_cb` forwards a chunk unless `body_too_large`, when it fails the
transfer and curl calls it no more. The final response's decoded body
reaches `write_cb` as chunks, in order.

## Where this model says more than the code
* Chunks are any sizes curl may choose.
* `cl` is any Content-Length: the response's, if unencoded and known
  (`some`), else `none`.

## Where it says less
* Pausing (`stream_window`): a chunk refused with a pause is offered again
  unchanged and is not counted, so it is the same chunk here. What a
  failure does to the transfer is `Flow/`'s business (`P.limits`).
* `curl_off_t` overflow: the counts here are `Nat`; a body of 2^63 bytes
  is out of reach.
-/

namespace KatipoProofs.Limit

/-- Sum of chunk sizes. -/
def total : List Nat → Nat
  | [] => 0
  | c :: cs => c + total cs

/-- `body_too_large` with `body_size = n` for a chunk of `c` bytes: the
verdict, and `body_size` after. -/
def tooLarge (limit : Nat) (cl : Option Nat) (n c : Nat) : Bool × Nat :=
  if n == 0 && cl.any (limit < ·) then (true, n)
  else (decide (limit < n + c), n + c)

/-- `write_cb` over the chunks, from `body_size = n`: the chunks it
forwards, and whether it failed the transfer. -/
def run (limit : Nat) (cl : Option Nat) : Nat → List Nat → List Nat × Bool
  | _, [] => ([], false)
  | n, c :: cs =>
    if (tooLarge limit cl n c).1 then ([], true)
    else let r := run limit cl (tooLarge limit cl n c).2 cs; (c :: r.1, r.2)

end KatipoProofs.Limit
