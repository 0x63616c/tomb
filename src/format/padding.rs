use rand::rngs::OsRng;
use rand::RngCore;

fn ilog2(n: usize) -> u32 {
    (usize::BITS - 1) - n.leading_zeros()
}

pub fn padme_length(len: usize) -> usize {
    if len <= 256 {
        return 256;
    }
    let e = ilog2(len);
    let s = ilog2(e as usize) + 1;
    let last_bits = e - s;
    let bit_mask = (1usize << last_bits) - 1;
    (len + bit_mask) & !bit_mask
}

pub fn pad(data: &[u8]) -> Vec<u8> {
    let padded_len = padme_length(data.len());
    let mut out = data.to_vec();
    let pad_len = padded_len - data.len();
    if pad_len > 0 {
        let mut padding = vec![0u8; pad_len];
        OsRng.fill_bytes(&mut padding);
        out.extend_from_slice(&padding);
    }
    out
}

pub fn unpad(data: &[u8], original_size: usize) -> Vec<u8> {
    data[..original_size].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_small_input_rounds_to_256() {
        assert_eq!(padme_length(1), 256);
        assert_eq!(padme_length(100), 256);
        assert_eq!(padme_length(256), 256);
    }

    #[test]
    fn padme_output_gte_input() {
        for size in [257, 500, 1000, 4096, 65536, 1_000_000] {
            assert!(
                padme_length(size) >= size,
                "padme_length({size}) was {}",
                padme_length(size)
            );
        }
    }

    #[test]
    fn padme_overhead_within_12_percent() {
        for size in [1000, 4096, 65536, 1_000_000] {
            let padded = padme_length(size);
            let overhead = (padded - size) as f64 / size as f64;
            assert!(overhead <= 0.12, "overhead for {size} was {overhead:.3}");
        }
    }

    #[test]
    fn pad_unpad_round_trip() {
        let data = b"hello world this is test data";
        let padded = pad(data);
        assert!(padded.len() >= data.len());
        let unpadded = unpad(&padded, data.len());
        assert_eq!(unpadded, data);
    }
}
