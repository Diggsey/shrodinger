use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct RangeSet {
    pub(crate) ranges: Vec<Range<u64>>,
}

impl RangeSet {
    fn simplify(&mut self) {
        let mut i = 0;
        while i < self.ranges.len() {
            let r1 = self.ranges[i].clone();
            if r1.is_empty() {
                self.ranges.remove(i);
                continue;
            } else if i > 0 {
                let r0 = &mut self.ranges[i - 1];
                if r0.end == r1.start {
                    r0.end = r1.end;
                    self.ranges.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    pub fn replace(&mut self, old_index: u64, new_index: u64) -> bool {
        for i in 0..self.ranges.len() {
            let r = &mut self.ranges[i];
            if r.contains(&old_index) {
                if r.start == old_index && r.end == old_index + 1 {
                    r.start = new_index;
                    r.end = new_index + 1;
                } else if r.start == old_index {
                    r.start += 1;
                    self.ranges.insert(i, new_index..(new_index + 1));
                } else if r.end == old_index + 1 {
                    r.end -= 1;
                    self.ranges.insert(i + 1, new_index..(new_index + 1));
                } else {
                    let old_end = r.end;
                    r.end = old_index;
                    self.ranges.insert(i + 1, (old_index + 1)..old_end);
                    self.ranges.insert(i + 1, new_index..(new_index + 1));
                }
                self.simplify();
                return true;
            }
        }
        false
    }

    pub fn add(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        self.ranges.push(range);
        self.simplify();
    }

    pub fn length(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }

    pub fn shrink(&mut self, mut count: u64) -> Vec<Range<u64>> {
        let mut result = Vec::new();
        while count > 0 && !self.ranges.is_empty() {
            let r = &mut self.ranges[0];
            let length = r.end - r.start;
            if length <= count {
                count -= length;
                result.push(r.start..r.end);
                self.ranges.remove(0);
                continue;
            } else {
                r.end -= count;
                result.push(r.end..(r.end + count));
                break;
            }
        }
        result
    }
}

#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct SortedRangeSet {
    pub(crate) ranges: Vec<Range<u64>>,
}

impl SortedRangeSet {
    pub fn length(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }

    pub fn add(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        for i in 0..self.ranges.len() {
            let r = &self.ranges[i];
            if range.end < r.start {
                self.ranges.insert(i, range);
                return;
            } else if range.start > r.end {
                continue;
            } else {
                let new_start = std::cmp::min(range.start, r.start);
                let mut new_end = std::cmp::max(range.end, r.end);
                let mut j = i + 1;
                while j < self.ranges.len() {
                    let r2 = &self.ranges[j];
                    if new_end < r2.start {
                        break;
                    }
                    new_end = std::cmp::max(new_end, r2.end);
                    j += 1;
                }
                self.ranges
                    .splice(i..j, std::iter::once(new_start..new_end));
                return;
            }
        }
        self.ranges.push(range);
    }

    pub fn remove(&mut self, index: u64) -> bool {
        for i in 0..self.ranges.len() {
            let r = self.ranges[i].clone();
            if r.contains(&index) {
                if r.start < index {
                    self.ranges[i].end = index;
                    if index + 1 < r.end {
                        self.ranges.insert(i + 1, index + 1..r.end);
                    }
                } else if index + 1 < r.end {
                    self.ranges[i] = index + 1..r.end;
                } else {
                    // Single element range, remove it entirely
                    self.ranges.remove(i);
                }
                return true;
            }
        }
        false
    }

    pub fn remove_range_containing(&mut self, index: u64) -> Option<Range<u64>> {
        for i in 0..self.ranges.len() {
            let r = &self.ranges[i];
            if r.contains(&index) {
                return Some(self.ranges.remove(i));
            }
        }
        None
    }

    pub fn take(&mut self, mut count: u64) -> (RangeSet, u64) {
        let mut result = RangeSet::default();
        while count > 0 && !self.ranges.is_empty() {
            let r = &mut self.ranges[0];
            let length = r.end - r.start;
            if length <= count {
                result.ranges.push(r.start..r.end);
                count -= length;
                self.ranges.remove(0);
                continue;
            } else {
                result.ranges.push(r.start..(r.start + count));
                r.start += count;
                count = 0;
                break;
            }
        }
        (result, count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rangeset_new() {
        let rs = RangeSet::default();
        assert_eq!(rs.ranges.len(), 0);
        assert_eq!(rs.length(), 0);
    }

    #[test]
    fn test_rangeset_add_single_range() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..10);
        assert_eq!(rs.length(), 5);
    }

    #[test]
    fn test_rangeset_add_empty_range() {
        let mut rs = RangeSet::default();
        rs.add(5..5);
        assert_eq!(rs.ranges.len(), 0);
        assert_eq!(rs.length(), 0);
    }

    #[test]
    fn test_rangeset_add_adjacent_ranges() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        rs.add(10..15);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..15);
        assert_eq!(rs.length(), 10);
    }

    #[test]
    fn test_rangeset_add_overlapping_ranges() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        rs.add(8..12);
        // RangeSet doesn't merge overlapping ranges, only adjacent ones
        assert_eq!(rs.ranges.len(), 2);
        assert_eq!(rs.length(), 9); // 5 + 4 = 9
    }

    #[test]
    fn test_rangeset_add_multiple_ranges() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        rs.add(20..25);
        rs.add(15..18);
        assert_eq!(rs.ranges.len(), 3);
        assert_eq!(rs.length(), 13);
    }

    #[test]
    fn test_rangeset_length() {
        let mut rs = RangeSet::default();
        assert_eq!(rs.length(), 0);

        rs.add(5..10);
        assert_eq!(rs.length(), 5);

        rs.add(20..30);
        assert_eq!(rs.length(), 15);

        rs.add(10..15);
        // After adding 10..15, it merges with 5..10 to become 5..15
        // Total: 5..15 (10) + 20..30 (10) = 20
        assert_eq!(rs.length(), 20);
    }

    #[test]
    fn test_rangeset_replace_single_element_range() {
        let mut rs = RangeSet::default();
        rs.add(5..6);
        assert!(rs.replace(5, 10));
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 10..11);
    }

    #[test]
    fn test_rangeset_replace_at_start() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        assert!(rs.replace(5, 20));
        assert_eq!(rs.ranges.len(), 2);
        assert_eq!(rs.ranges[0], 20..21);
        assert_eq!(rs.ranges[1], 6..10);
    }

    #[test]
    fn test_rangeset_replace_at_end() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        assert!(rs.replace(9, 20));
        assert_eq!(rs.ranges.len(), 2);
        assert_eq!(rs.ranges[0], 5..9);
        assert_eq!(rs.ranges[1], 20..21);
    }

    #[test]
    fn test_rangeset_replace_in_middle() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        assert!(rs.replace(7, 20));
        assert_eq!(rs.ranges.len(), 3);
        assert_eq!(rs.ranges[0], 5..7);
        assert_eq!(rs.ranges[1], 20..21);
        assert_eq!(rs.ranges[2], 8..10);
    }

    #[test]
    fn test_rangeset_replace_not_found() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        assert!(!rs.replace(15, 20));
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..10);
    }

    #[test]
    fn test_rangeset_shrink_empty() {
        let mut rs = RangeSet::default();
        let removed = rs.shrink(5);
        assert_eq!(removed.len(), 0);
    }

    #[test]
    fn test_rangeset_shrink_partial_range() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        let removed = rs.shrink(3);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], 7..10);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..7);
        assert_eq!(rs.length(), 2);
    }

    #[test]
    fn test_rangeset_shrink_entire_range() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        let removed = rs.shrink(5);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], 5..10);
        assert_eq!(rs.ranges.len(), 0);
        assert_eq!(rs.length(), 0);
    }

    #[test]
    fn test_rangeset_shrink_multiple_ranges() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        rs.add(15..20);
        let removed = rs.shrink(8);
        assert_eq!(removed.len(), 2);
        assert_eq!(removed[0], 5..10);
        assert_eq!(removed[1], 17..20);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 15..17);
        assert_eq!(rs.length(), 2);
    }

    #[test]
    fn test_rangeset_shrink_more_than_available() {
        let mut rs = RangeSet::default();
        rs.add(5..10);
        let removed = rs.shrink(10);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0], 5..10);
        assert_eq!(rs.ranges.len(), 0);
    }

    #[test]
    fn test_sortedrangeset_new() {
        let srs = SortedRangeSet::default();
        assert_eq!(srs.ranges.len(), 0);
    }

    #[test]
    fn test_sortedrangeset_add_single_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..10);
    }

    #[test]
    fn test_sortedrangeset_add_empty_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..5);
        assert_eq!(srs.ranges.len(), 0);
    }

    #[test]
    fn test_sortedrangeset_add_sorted_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        srs.add(15..20);
        srs.add(25..30);
        assert_eq!(srs.ranges.len(), 3);
        assert_eq!(srs.ranges[0], 5..10);
        assert_eq!(srs.ranges[1], 15..20);
        assert_eq!(srs.ranges[2], 25..30);
    }

    #[test]
    fn test_sortedrangeset_add_unsorted_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(15..20);
        srs.add(5..10);
        srs.add(25..30);
        assert_eq!(srs.ranges.len(), 3);
        assert_eq!(srs.ranges[0], 5..10);
        assert_eq!(srs.ranges[1], 15..20);
        assert_eq!(srs.ranges[2], 25..30);
    }

    #[test]
    fn test_sortedrangeset_add_adjacent_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        srs.add(10..15);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..15);
    }

    #[test]
    fn test_sortedrangeset_add_overlapping_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        srs.add(8..15);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..15);
    }

    #[test]
    fn test_sortedrangeset_add_contained_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..20);
        srs.add(10..15);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..20);
    }

    #[test]
    fn test_sortedrangeset_add_containing_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(10..15);
        srs.add(5..20);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..20);
    }

    #[test]
    fn test_sortedrangeset_add_merging_multiple_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        srs.add(15..20);
        srs.add(25..30);
        srs.add(8..27);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..30);
    }

    #[test]
    fn test_sortedrangeset_remove_from_empty() {
        let mut srs = SortedRangeSet::default();
        assert!(!srs.remove(5));
    }

    #[test]
    fn test_sortedrangeset_remove_not_found() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        assert!(!srs.remove(15));
        assert_eq!(srs.ranges.len(), 1);
    }

    #[test]
    fn test_sortedrangeset_remove_single_element_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..6);
        assert!(srs.remove(5));
        assert_eq!(srs.ranges.len(), 0);
    }

    #[test]
    fn test_sortedrangeset_remove_at_start() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        assert!(srs.remove(5));
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 6..10);
    }

    #[test]
    fn test_sortedrangeset_remove_at_end() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        assert!(srs.remove(9));
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 5..9);
    }

    #[test]
    fn test_sortedrangeset_remove_in_middle() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        assert!(srs.remove(7));
        assert_eq!(srs.ranges.len(), 2);
        assert_eq!(srs.ranges[0], 5..7);
        assert_eq!(srs.ranges[1], 8..10);
    }

    #[test]
    fn test_sortedrangeset_take_from_empty() {
        let mut srs = SortedRangeSet::default();
        let (rs, remaining) = srs.take(5);
        assert_eq!(rs.ranges.len(), 0);
        assert_eq!(remaining, 5);
    }

    #[test]
    fn test_sortedrangeset_take_partial_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        let (rs, remaining) = srs.take(3);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..8);
        assert_eq!(remaining, 0);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 8..10);
    }

    #[test]
    fn test_sortedrangeset_take_entire_range() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        let (rs, remaining) = srs.take(5);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..10);
        assert_eq!(remaining, 0);
        assert_eq!(srs.ranges.len(), 0);
    }

    #[test]
    fn test_sortedrangeset_take_multiple_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        srs.add(15..20);
        let (rs, remaining) = srs.take(8);
        assert_eq!(rs.ranges.len(), 2);
        assert_eq!(rs.ranges[0], 5..10);
        assert_eq!(rs.ranges[1], 15..18);
        assert_eq!(remaining, 0);
        assert_eq!(srs.ranges.len(), 1);
        assert_eq!(srs.ranges[0], 18..20);
    }

    #[test]
    fn test_sortedrangeset_take_more_than_available() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        let (rs, remaining) = srs.take(10);
        assert_eq!(rs.ranges.len(), 1);
        assert_eq!(rs.ranges[0], 5..10);
        assert_eq!(remaining, 5);
        assert_eq!(srs.ranges.len(), 0);
    }

    #[test]
    fn test_sortedrangeset_take_all_ranges() {
        let mut srs = SortedRangeSet::default();
        srs.add(5..10);
        srs.add(15..20);
        srs.add(25..30);
        let (rs, remaining) = srs.take(15);
        assert_eq!(rs.ranges.len(), 3);
        assert_eq!(rs.ranges[0], 5..10);
        assert_eq!(rs.ranges[1], 15..20);
        assert_eq!(rs.ranges[2], 25..30);
        assert_eq!(remaining, 0);
        assert_eq!(srs.ranges.len(), 0);
    }
}
