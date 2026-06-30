use super::*;
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead};
use std::str;
use std::string::String;

/// Wraps a `std::io::BufRead` buffered byte stream and decode it as UTF-8.
///
/// # Examples
///
/// Lossy decoding of an in-memory byte stream:
///
/// ```
/// use std::io::BufReader;
/// use utf8_zero::BufReadDecoder;
///
/// let input = b"Hello \xF0\x9F\x8C\x8D\xC0world";
/// let reader = BufReader::new(&input[..]);
/// let output = BufReadDecoder::read_to_string_lossy(reader).unwrap();
/// assert_eq!(output, "Hello \u{1F30D}\u{FFFD}world");
/// ```
///
/// Strict chunk-by-chunk decoding:
///
/// ```
/// use std::io::BufReader;
/// use utf8_zero::{BufReadDecoder, BufReadDecoderError};
///
/// let input = b"ok\xFFend";
/// let mut decoder = BufReadDecoder::new(BufReader::new(&input[..]));
/// let mut parts = Vec::new();
/// while let Some(result) = decoder.next_strict() {
///     match result {
///         Ok(s) => parts.push(format!("str:{s}")),
///         Err(BufReadDecoderError::InvalidByteSequence(b)) => {
///             parts.push(format!("err:{b:02x?}"));
///         }
///         Err(BufReadDecoderError::Io(e)) => panic!("io error: {e}"),
///     }
/// }
/// assert_eq!(parts, vec!["str:ok", "err:[ff]", "str:end"]);
/// ```
pub struct BufReadDecoder<B: BufRead> {
    buf_read: B,
    bytes_consumed: usize,
    incomplete: Incomplete,
}

/// Error returned by [`BufReadDecoder::next_strict()`].
#[derive(Debug)]
pub enum BufReadDecoderError<'a> {
    /// Represents one UTF-8 error in the byte stream.
    ///
    /// In lossy decoding, each such error should be replaced with U+FFFD.
    /// (See `BufReadDecoder::next_lossy` and `BufReadDecoderError::lossy`.)
    InvalidByteSequence(&'a [u8]),

    /// An I/O error from the underlying byte stream
    Io(io::Error),
}

impl<'a> BufReadDecoderError<'a> {
    /// Replace UTF-8 errors with U+FFFD
    pub fn lossy(self) -> Result<&'static str, io::Error> {
        match self {
            BufReadDecoderError::Io(error) => Err(error),
            BufReadDecoderError::InvalidByteSequence(_) => Ok(REPLACEMENT_CHARACTER),
        }
    }
}

impl<'a> fmt::Display for BufReadDecoderError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BufReadDecoderError::InvalidByteSequence(bytes) => {
                write!(f, "invalid byte sequence: {:02x?}", bytes)
            }
            BufReadDecoderError::Io(ref err) => write!(f, "underlying bytestream error: {}", err),
        }
    }
}

impl<'a> Error for BufReadDecoderError<'a> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            BufReadDecoderError::InvalidByteSequence(_) => None,
            BufReadDecoderError::Io(ref err) => Some(err),
        }
    }
}

impl<B: BufRead> BufReadDecoder<B> {
    /// This is to `Read::read_to_string` what `String::from_utf8_lossy` is to `String::from_utf8`.
    pub fn read_to_string_lossy(buf_read: B) -> io::Result<String> {
        let mut decoder = Self::new(buf_read);
        let mut string = String::new();
        while let Some(result) = decoder.next_lossy() {
            string.push_str(result?)
        }
        Ok(string)
    }

    /// Wrap a buffered byte stream for UTF-8 decoding.
    pub fn new(buf_read: B) -> Self {
        Self {
            buf_read,
            bytes_consumed: 0,
            incomplete: Incomplete::empty(),
        }
    }

    /// Same as `BufReadDecoder::next_strict`, but replace UTF-8 errors with U+FFFD.
    pub fn next_lossy(&mut self) -> Option<io::Result<&str>> {
        self.next_strict()
            .map(|result| result.or_else(|e| e.lossy()))
    }

    /// Decode and consume the next chunk of UTF-8 input.
    ///
    /// This method is intended to be called repeatedly until it returns `None`,
    /// which represents EOF from the underlying byte stream.
    /// This is similar to `Iterator::next`,
    /// except that decoded chunks borrow the decoder (~iterator)
    /// so they need to be handled or copied before the next chunk can start decoding.
    pub fn next_strict<'a>(&'a mut self) -> Option<Result<&'a str, BufReadDecoderError<'a>>> {
        macro_rules! try_io {
            ($io_result: expr) => {
                match $io_result {
                    Ok(value) => value,
                    Err(error) => return Some(Err(BufReadDecoderError::Io(error))),
                }
            };
        }
        loop {
            if self.bytes_consumed > 0 {
                self.buf_read.consume(self.bytes_consumed);
                self.bytes_consumed = 0;
            }
            let buf = try_io!(self.buf_read.fill_buf());

            if self.incomplete.is_empty() {
                if buf.is_empty() {
                    return None; // EOF
                }
                match str::from_utf8(buf) {
                    Ok(_) => {
                        let len = buf.len();
                        self.bytes_consumed = len;
                        // SAFETY:
                        // Lifetime Extension: The returned slice must be valid for `'a`. We helper-extend
                        // the lifetime of `buf` to `'a` using `from_raw_parts`. This is safe because the
                        // returned reference mutably borrows `self` for `'a`, preventing any other
                        // operations on `self.buf_read` (such as `consume` or `fill_buf`) while the
                        // reference is alive. The contract of `BufRead::fill_buf` guarantees the buffer
                        // remains valid until the next I/O or consume/fill_buf call.
                        //
                        // NOTE: This unsafe lifetime extension is a workaround for a borrow checker
                        // limitation regarding conditional returns from loops (NLL Problem Case #3).
                        // See upstream issue: https://github.com/rust-lang/rust/issues/51545
                        // This can be removed once Polonius (the next-gen borrow checker) is stable.
                        let extended = unsafe { core::slice::from_raw_parts(buf.as_ptr(), len) };
                        // SAFETY:
                        // UTF-8 Validity: `str::from_utf8(buf)` returned `Ok(_)`, so the entire `buf`
                        // (and thus `extended`) is valid UTF-8.
                        return Some(Ok(unsafe { str::from_utf8_unchecked(extended) }));
                    }
                    Err(error) => {
                        let valid_up_to = error.valid_up_to();
                        if valid_up_to > 0 {
                            self.bytes_consumed = valid_up_to;
                            // SAFETY:
                            // Lifetime Extension: See justification above (in the Ok(_) branch).
                            let extended = unsafe { core::slice::from_raw_parts(buf.as_ptr(), valid_up_to) };
                            // SAFETY:
                            // UTF-8 Validity: `str::from_utf8(buf)` returned `Err`, but the prefix of `buf`
                            // up to `valid_up_to` is guaranteed to be valid UTF-8 by `Utf8Error::valid_up_to`
                            // invariants (std axiom).
                            return Some(Ok(unsafe { str::from_utf8_unchecked(extended) }));
                        }
                        match error.error_len() {
                            Some(invalid_sequence_length) => {
                                self.bytes_consumed = invalid_sequence_length;
                                // SAFETY:
                                // Lifetime Extension: See justification above (in the Ok(_) branch).
                                let extended = unsafe { core::slice::from_raw_parts(buf.as_ptr(), invalid_sequence_length) };
                                return Some(Err(BufReadDecoderError::InvalidByteSequence(extended)));
                            }
                            None => {
                                self.bytes_consumed = buf.len();
                                self.incomplete = Incomplete::new(buf);
                                // need more input bytes
                                continue;
                            }
                        }
                    }
                }
            } else {
                if buf.is_empty() {
                    let bytes = self.incomplete.take_buffer();
                    return Some(Err(BufReadDecoderError::InvalidByteSequence(bytes)));
                }
                let (consumed, opt_result) = self.incomplete.try_complete_offsets(buf);
                self.bytes_consumed = consumed;
                match opt_result {
                    None => {
                        // need more input bytes
                        continue;
                    }
                    Some(result) => {
                        let bytes = self.incomplete.take_buffer();
                        match result {
                            // SAFETY:
                            // - Contract: `bytes` must be valid UTF-8.
                            // - Evidence: `result` being `Ok(())` means `self.incomplete.try_complete`
                            //   successfully completed and validated the buffered bytes as UTF-8.
                            //   By the safety-usable invariant of `try_complete_offsets` (proven inline there),
                            //   the buffered bytes `self.incomplete.buffer[..self.incomplete.buffer_len]`
                            //   (which `take_buffer()` returns) are valid UTF-8.
                            Ok(()) => return Some(Ok(unsafe { str::from_utf8_unchecked(bytes) })),
                            Err(()) => return Some(Err(BufReadDecoderError::InvalidByteSequence(bytes))),
                        }
                    }
                }
            }
        }
    }
}
