#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::BufReader;

fuzz_target!(|data: &[u8]| {
    let expected = String::from_utf8_lossy(data);

    let reader = BufReader::with_capacity(
        // Use a small buffer to exercise the incomplete-sequence path more often.
        // Minimum capacity is 1; avoid 0 which would be useless.
        std::cmp::max(1, data.len() / 4),
        data,
    );

    let output = utf8::BufReadDecoder::read_to_string_lossy(reader)
        .expect("read_to_string_lossy should not return an io::Error on an in-memory reader");

    assert_eq!(
        output, *expected,
        "BufReadDecoder output differs from String::from_utf8_lossy"
    );
});
