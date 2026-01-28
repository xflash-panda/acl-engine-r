//! Succinct Trie data structure for memory-efficient domain matching.
//!
//! Uses bitmap-based compression with rank/select indices to dramatically
//! reduce memory overhead compared to traditional pointer-based tries.
//!
//! This is a port of the Go implementation from sing-box/sing-trie.

/// Succinct set data structure
#[derive(Debug, Clone, Default)]
pub struct SuccinctSet {
    /// Leaf node bitmap - marks domain termination points
    pub(crate) leaves: Vec<u64>,
    /// Node boundary bitmap - 0 = label, 1 = node end
    pub(crate) label_bitmap: Vec<u64>,
    /// Edge character labels
    pub(crate) labels: Vec<u8>,
    /// Rank index for fast bit counting
    pub(crate) ranks: Vec<i32>,
    /// Select index for fast position lookup
    pub(crate) selects: Vec<i32>,
}

impl SuccinctSet {
    /// Create a new succinct set from sorted keys (must be pre-sorted)
    pub fn new(sorted_keys: &[String]) -> Self {
        if sorted_keys.is_empty() {
            return Self::default();
        }

        let keys: Vec<&[u8]> = sorted_keys.iter().map(|s| s.as_bytes()).collect();
        let mut builder = SuccinctSetBuilder::new();
        builder.build(&keys);
        builder.finish()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

/// Builder for SuccinctSet using BFS
struct SuccinctSetBuilder {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
}

impl SuccinctSetBuilder {
    fn new() -> Self {
        Self {
            leaves: Vec::new(),
            label_bitmap: Vec::new(),
            labels: Vec::new(),
        }
    }

    fn build(&mut self, keys: &[&[u8]]) {
        if keys.is_empty() {
            return;
        }

        // BFS queue: (start_idx, end_idx, depth)
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((0usize, keys.len(), 0usize));

        while let Some((start, end, depth)) = queue.pop_front() {
            if start >= end {
                // Empty node - add boundary marker
                let labels_len = self.labels.len();
                set_bit(&mut self.label_bitmap, labels_len, true);
                continue;
            }

            let mut i = start;
            while i < end {
                // Get character at current depth (0 means end of string)
                let ch = keys[i].get(depth).copied().unwrap_or(0);

                // Find all keys with the same character at this depth
                let mut j = i + 1;
                while j < end {
                    let next_ch = keys[j].get(depth).copied().unwrap_or(0);
                    if next_ch != ch {
                        break;
                    }
                    j += 1;
                }

                // Add label
                self.labels.push(ch);
                let label_idx = self.labels.len() - 1;

                // Mark as leaf if this is the end of any key
                let is_leaf = keys[i..j].iter().any(|k| k.len() == depth || (ch == 0));
                set_bit(&mut self.leaves, label_idx, is_leaf);

                // Don't process children if this is end-of-string marker
                if ch != 0 {
                    queue.push_back((i, j, depth + 1));
                }

                i = j;
            }

            // Mark node boundary (end of this node's children list)
            let labels_len = self.labels.len();
            set_bit(&mut self.label_bitmap, labels_len, true);
        }
    }

    fn finish(self) -> SuccinctSet {
        let ranks = index_rank64(&self.label_bitmap);
        let selects = index_select32(&self.label_bitmap);

        SuccinctSet {
            leaves: self.leaves,
            label_bitmap: self.label_bitmap,
            labels: self.labels,
            ranks,
            selects,
        }
    }
}

/// Set bit at index in bitmap
fn set_bit(bitmap: &mut Vec<u64>, idx: usize, value: bool) {
    let word_idx = idx / 64;
    let bit_idx = idx % 64;

    while bitmap.len() <= word_idx {
        bitmap.push(0);
    }

    if value {
        bitmap[word_idx] |= 1u64 << bit_idx;
    }
}

/// Get bit at index from bitmap
#[inline]
pub fn get_bit(bitmap: &[u64], idx: usize) -> bool {
    let word_idx = idx / 64;
    if word_idx >= bitmap.len() {
        return false;
    }
    let bit_idx = idx % 64;
    (bitmap[word_idx] >> bit_idx) & 1 == 1
}

/// Build rank index for bitmap (cumulative count of 1s)
fn index_rank64(bitmap: &[u64]) -> Vec<i32> {
    let mut ranks = Vec::with_capacity(bitmap.len() + 1);
    let mut count = 0i32;
    ranks.push(0);

    for &word in bitmap {
        count += word.count_ones() as i32;
        ranks.push(count);
    }

    ranks
}

/// Build select index for bitmap (positions of 1s)
fn index_select32(bitmap: &[u64]) -> Vec<i32> {
    let mut selects = Vec::new();

    for (word_idx, &word) in bitmap.iter().enumerate() {
        for bit_idx in 0..64 {
            if (word >> bit_idx) & 1 == 1 {
                selects.push((word_idx * 64 + bit_idx) as i32);
            }
        }
    }

    selects
}

/// Count zeros up to position (exclusive) using rank index
#[inline]
pub fn count_zeros(bitmap: &[u64], ranks: &[i32], idx: usize) -> usize {
    if bitmap.is_empty() || idx == 0 {
        return 0;
    }

    let word_idx = idx / 64;
    let bit_idx = idx % 64;

    // Get rank (count of 1s) before this word
    let rank_before = if word_idx < ranks.len() {
        ranks[word_idx] as usize
    } else {
        *ranks.last().unwrap_or(&0) as usize
    };

    // Count 1s within the current word up to bit_idx
    let ones_in_word = if word_idx < bitmap.len() && bit_idx > 0 {
        (bitmap[word_idx] & ((1u64 << bit_idx) - 1)).count_ones() as usize
    } else {
        0
    };

    // zeros = total_bits - ones
    idx - (rank_before + ones_in_word)
}

/// Find position of the i-th 1 in bitmap using select index
#[inline]
pub fn select_ith_one(_bitmap: &[u64], _ranks: &[i32], selects: &[i32], i: usize) -> usize {
    if i < selects.len() {
        selects[i] as usize
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_bit() {
        let bitmap = vec![0b1010u64];
        assert!(!get_bit(&bitmap, 0));
        assert!(get_bit(&bitmap, 1));
        assert!(!get_bit(&bitmap, 2));
        assert!(get_bit(&bitmap, 3));
    }

    #[test]
    fn test_empty_set() {
        let set = SuccinctSet::new(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn test_single_key() {
        let set = SuccinctSet::new(&["test".to_string()]);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_multiple_keys() {
        let mut keys = vec![
            "moc.elgoog".to_string(),   // google.com reversed
            "moc.koobecaf".to_string(), // facebook.com reversed
        ];
        keys.sort();
        let set = SuccinctSet::new(&keys);
        assert!(!set.is_empty());
        assert!(!set.labels.is_empty());
    }
}
