#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    /// Positions at which to split `data` into chunks fed to the decoder.
    /// Values are taken modulo (data.len() + 1) to produce valid split points.
    split_points: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let expected = String::from_utf8_lossy(&input.data);

    // Build sorted, deduplicated split points in [0, data.len()].
    let len = input.data.len();
    let mut splits: Vec<usize> = input
        .split_points
        .iter()
        .map(|&p| (p as usize) % (len + 1))
        .collect();
    splits.push(0);
    splits.push(len);
    splits.sort_unstable();
    splits.dedup();

    // Feed chunks through LossyDecoder and collect output.
    let mut output = String::new();
    {
        let mut decoder = utf8::LossyDecoder::new(|s| output.push_str(s));
        for window in splits.windows(2) {
            let chunk = &input.data[window[0]..window[1]];
            decoder.feed(chunk);
        }
        // decoder is dropped here, finalizing any trailing incomplete sequence
    }

    assert_eq!(
        output, *expected,
        "LossyDecoder output differs from String::from_utf8_lossy"
    );
});
