#![no_main]

use libfuzzer_sys::fuzz_target;
use std::str;

fuzz_target!(|data: &[u8]| {
    let result = utf8_zero::decode(data);

    match result {
        Ok(valid) => {
            // If decode says OK, std must agree and the entire input is valid UTF-8.
            assert_eq!(valid.as_bytes(), data);
            assert!(str::from_utf8(data).is_ok());
        }
        Err(utf8_zero::DecodeError::Invalid {
            valid_prefix,
            invalid_sequence,
            remaining_input,
        }) => {
            // valid_prefix must be genuinely valid UTF-8.
            assert!(str::from_utf8(valid_prefix.as_bytes()).is_ok());

            // The three slices must exactly cover the input.
            assert_eq!(
                valid_prefix.len() + invalid_sequence.len() + remaining_input.len(),
                data.len()
            );

            // invalid_sequence must be non-empty.
            assert!(!invalid_sequence.is_empty());

            // std::str::from_utf8 must also report an error at the same position.
            let std_err = str::from_utf8(data).unwrap_err();
            assert_eq!(std_err.valid_up_to(), valid_prefix.len());
        }
        Err(utf8_zero::DecodeError::Incomplete {
            valid_prefix,
            incomplete_suffix,
        }) => {
            // valid_prefix must be genuinely valid UTF-8.
            assert!(str::from_utf8(valid_prefix.as_bytes()).is_ok());

            // The suffix length must be 1..=3 (incomplete multi-byte sequence).
            let suffix_len = incomplete_suffix.buffer_len as usize;
            assert!(suffix_len >= 1 && suffix_len <= 3);

            // valid_prefix + incomplete_suffix must cover the input.
            assert_eq!(valid_prefix.len() + suffix_len, data.len());

            // std must also report an error at the same position with no error_len (incomplete).
            let std_err = str::from_utf8(data).unwrap_err();
            assert_eq!(std_err.valid_up_to(), valid_prefix.len());
            assert!(std_err.error_len().is_none());
        }
    }
});
