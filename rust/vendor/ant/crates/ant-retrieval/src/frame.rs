//! Bounded-growth reader for the body of a length-delimited frame.
//!
//! Every protobuf stream (retrieval, pushsync, hive, pricing, pseudosettle,
//! swap, pullsync, the handshake) reads a varint length and then that many
//! body bytes. Allocating `vec![0u8; len]` as soon as the length passes its
//! cap lets a peer pin up to the cap per stream by declaring a large frame
//! and sending nothing (#203). `read_frame_body` instead grows the buffer
//! in steps sized by what has already arrived, so a stalled frame holds at
//! most [`FRAME_READ_STEP`] or twice the bytes received, and the buffer
//! never grows past `len` (a complete frame ends at exactly `len`).

use futures::io::{AsyncRead, AsyncReadExt};

/// Smallest growth step. A frame shorter than this is allocated in one go.
pub const FRAME_READ_STEP: usize = 16 * 1024;

/// Read exactly `len` body bytes from `r`.
///
/// The buffer grows by `max(received, FRAME_READ_STEP)`, capped at what is
/// still missing, so its size is at most `min(len, received +
/// max(received, FRAME_READ_STEP))`. Fewer than `len` bytes before EOF is
/// `UnexpectedEof` ("frame truncated: N of LEN bytes"), the same error kind
/// `read_exact` gave.
pub async fn read_frame_body<R: AsyncRead + Unpin + ?Sized>(
    r: &mut R,
    len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut filled = 0;
    while filled < len {
        if filled == buf.len() {
            let grow = filled.max(FRAME_READ_STEP).min(len - filled);
            buf.reserve_exact(grow);
            buf.resize(filled + grow, 0);
        }
        match r.read(&mut buf[filled..]).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("frame truncated: {filled} of {len} bytes"),
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn complete_frame_at_cap_ends_at_exact_len() {
        let len = 128 * 1024;
        let wire = vec![0xAB; len + 2];
        let mut r: &[u8] = &wire;
        let body = read_frame_body(&mut r, len).await.unwrap();
        assert_eq!(body.len(), len);
        assert_eq!(body.capacity(), len, "no doubling past the frame");
        assert!(body.iter().all(|&b| b == 0xAB));
        assert_eq!(r.len(), 2, "trailing bytes stay on the stream");
    }

    #[tokio::test]
    async fn short_body_is_unexpected_eof() {
        let mut r: &[u8] = &[1, 2, 3];
        let err = read_frame_body(&mut r, 100).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("3 of 100"), "{err}");
    }

    #[tokio::test]
    async fn empty_frame_reads_nothing() {
        let mut r: &[u8] = &[7];
        assert_eq!(read_frame_body(&mut r, 0).await.unwrap(), Vec::<u8>::new());
        assert_eq!(r, &[7]);
    }

    /// A peer that declares a large frame and then stalls only pins one
    /// growth step, not the declared length.
    #[tokio::test]
    async fn stalled_frame_grows_with_received_bytes() {
        use std::pin::Pin;
        use std::sync::{Arc, Mutex};
        use std::task::{Context, Poll};

        /// Hands out `data`, then stays pending forever, recording the
        /// largest body buffer seen: bytes already delivered plus the
        /// spare slice each read is offered (`read_frame_body` always
        /// offers `buf[filled..]`).
        struct Stall {
            data: Vec<u8>,
            delivered: usize,
            offered: Arc<Mutex<usize>>,
        }
        impl AsyncRead for Stall {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                out: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                let mut o = self.offered.lock().unwrap();
                *o = (*o).max(self.delivered + out.len());
                drop(o);
                if self.data.is_empty() {
                    return Poll::Pending;
                }
                let n = out.len().min(self.data.len());
                out[..n].copy_from_slice(&self.data[..n]);
                self.data.drain(..n);
                self.delivered += n;
                Poll::Ready(Ok(n))
            }
        }

        let offered = Arc::new(Mutex::new(0));
        let mut r = Stall {
            data: Vec::new(),
            delivered: 0,
            offered: offered.clone(),
        };
        let fut = read_frame_body(&mut r, 128 * 1024);
        assert!(futures::poll!(Box::pin(fut)).is_pending());
        assert_eq!(*offered.lock().unwrap(), FRAME_READ_STEP);

        // 20 KiB arrive, then nothing: the buffer grew 16 KiB -> 32 KiB,
        // under twice what arrived and well under the declared 128 KiB.
        *offered.lock().unwrap() = 0;
        let mut r = Stall {
            data: vec![1; 20 * 1024],
            delivered: 0,
            offered: offered.clone(),
        };
        let fut = read_frame_body(&mut r, 128 * 1024);
        assert!(futures::poll!(Box::pin(fut)).is_pending());
        assert_eq!(*offered.lock().unwrap(), 32 * 1024);

        // 100 KiB arrive: the next step is capped at the frame's end.
        *offered.lock().unwrap() = 0;
        let mut r = Stall {
            data: vec![1; 100 * 1024],
            delivered: 0,
            offered: offered.clone(),
        };
        let fut = read_frame_body(&mut r, 128 * 1024);
        assert!(futures::poll!(Box::pin(fut)).is_pending());
        assert_eq!(*offered.lock().unwrap(), 128 * 1024);
    }
}
