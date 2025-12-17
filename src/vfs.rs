use std::{collections::HashMap, ops::Range};

use anyhow::Error;
use serde::{Deserialize, Serialize};

use crate::block::{BLOCK_DATA_SIZE, DecryptionError, EncryptedBlockDevice};

pub struct Vfs {
    device: EncryptedBlockDevice,
    metadata: VfsMetadata,
}

#[derive(Serialize, Deserialize, Default)]
struct VfsMetadata {
    metadata_blocks: u64,
    allocated_blocks: u64,
    items: HashMap<String, ItemMetadata>,
    free_ranges: SortedRangeSet,
}

struct RelocatedBlock {
    old_index: u64,
    new_index: u64,
}

impl VfsMetadata {
    fn allocate(&mut self, mut count: u64) -> RangeSet {
        let (mut taken_ranges, remaining) = self.free_ranges.take(count);
        taken_ranges.add(self.allocated_blocks..(self.allocated_blocks + remaining));
        self.allocated_blocks += remaining;
        taken_ranges
    }
    fn steal_block(&mut self, index: u64) -> Option<RelocatedBlock> {
        if index < self.metadata_blocks {
            panic!("Cannot steal metadata blocks");
        } else if index >= self.allocated_blocks {
            self.free_ranges.add(self.allocated_blocks..index);
            self.allocated_blocks = index + 1;
            None
        } else if self.free_ranges.remove(index) {
            None
        } else {
            let new_index = self.allocate(1).ranges[0].start;
            for item in self.items.values_mut() {
                if item.blocks.replace(index, new_index) {
                    return Some(RelocatedBlock {
                        old_index: index,
                        new_index,
                    });
                }
            }
            panic!("Block {} not found in any item", index);
        }
    }
    fn steal_blocks(&mut self, range: Range<u64>) -> Vec<RelocatedBlock> {
        range
            .into_iter()
            .filter_map(|idx| self.steal_block(idx))
            .collect()
    }
}

#[derive(Serialize, Deserialize, Default)]
struct RangeSet {
    ranges: Vec<Range<u64>>,
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
    fn replace(&mut self, old_index: u64, new_index: u64) -> bool {
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
    fn add(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        self.ranges.push(range);
        self.simplify();
    }
    fn length(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }
    fn shrink(&mut self, mut count: u64) -> Vec<Range<u64>> {
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

#[derive(Serialize, Deserialize, Default)]
struct SortedRangeSet {
    ranges: Vec<Range<u64>>,
}

impl SortedRangeSet {
    fn add(&mut self, range: Range<u64>) {
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
                self.ranges.splice(i..j, [new_start..new_end]);
                return;
            }
        }
        self.ranges.push(range);
    }

    fn remove(&mut self, index: u64) -> bool {
        for i in 0..self.ranges.len() {
            let r = self.ranges[i].clone();
            if r.contains(&index) {
                if r.start < index {
                    self.ranges[i].end = index;
                }
                if index + 1 < r.end {
                    self.ranges.insert(i + 1, index + 1..r.end);
                }
                return true;
            }
        }
        false
    }

    fn take(&mut self, mut count: u64) -> (RangeSet, u64) {
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

const ITEM_FLAG_DIRECTORY: u32 = 0x1;

#[derive(Serialize, Deserialize)]
struct ItemMetadata {
    flags: u32,
    size: u64,
    blocks: RangeSet,
}

pub struct StatItem {
    pub flags: u32,
    pub size: u64,
}

#[derive(thiserror::Error, Debug)]
#[error("Metadata overrun by {extra_blocks} blocks")]
pub struct MetadataOverrunError {
    pub extra_blocks: u64,
}

#[derive(thiserror::Error, Debug)]
#[error("Path not found")]
pub struct NotFoundError;

fn read_metadata(device: &mut EncryptedBlockDevice) -> Result<VfsMetadata, anyhow::Error> {
    fn read_metadata_inner(
        device: &mut EncryptedBlockDevice,
    ) -> Result<VfsMetadata, anyhow::Error> {
        let mut buffer = device.read_block(0)?;
        let mut block_idx = 1;
        let size =
            u64::from_le_bytes(buffer[..8].try_into().expect("Failed to read size")) as usize;
        while buffer.len() < size + 8 {
            let next_block = device.read_block(block_idx)?;
            buffer.extend_from_slice(&next_block);
            block_idx += 1;
        }
        Ok(bson::deserialize_from_slice(&buffer[8..(size + 8)])?)
    }
    read_metadata_inner(device).or_else(|e| {
        if e.is::<DecryptionError>() {
            Ok(VfsMetadata::default())
        } else {
            Err(e)
        }
    })
}

fn write_metadata(
    device: &mut EncryptedBlockDevice,
    value: &VfsMetadata,
) -> Result<(), anyhow::Error> {
    let mut buffer = bson::serialize_to_vec(value)?;
    buffer.extend(u64::to_le_bytes(buffer.len() as u64));
    buffer.rotate_right(8);
    buffer.resize(buffer.len().next_multiple_of(BLOCK_DATA_SIZE), 0);

    let num_blocks = (buffer.len() / BLOCK_DATA_SIZE) as u64;
    if num_blocks > value.metadata_blocks {
        return Err(MetadataOverrunError {
            extra_blocks: num_blocks - value.metadata_blocks,
        }
        .into());
    }

    device.write(0, &buffer)?;
    Ok(())
}

impl Vfs {
    pub fn new(mut device: EncryptedBlockDevice) -> Result<Self, Error> {
        let metadata = read_metadata(&mut device)?;
        Ok(Self { device, metadata })
    }
    pub fn save_metadata(&mut self) -> Result<(), Error> {
        while let Some(err) = write_metadata(&mut self.device, &self.metadata).map_or_else(
            |e| e.downcast::<MetadataOverrunError>().map(Some),
            |()| Ok(None),
        )? {
            let relocations = self.metadata.steal_blocks(
                self.metadata.allocated_blocks..(self.metadata.allocated_blocks + err.extra_blocks),
            );
            self.metadata.allocated_blocks += err.extra_blocks;
            for relocation in relocations {
                let block_data = self.device.read_block(relocation.old_index)?;
                self.device.write_block(relocation.new_index, block_data)?;
            }
        }
        self.device.flush()?;
        Ok(())
    }
    pub fn list_dir(&self, path: &str) -> Result<Vec<String>, Error> {
        let item = self.metadata.items.get(path).ok_or(NotFoundError)?;
        if item.flags & ITEM_FLAG_DIRECTORY == 0 {
            return Err(NotFoundError.into());
        }
        let prefix = format!("{}\\", path);
        Ok(self
            .metadata
            .items
            .keys()
            .filter(|k| {
                k.strip_prefix(&prefix)
                    .is_some_and(|rest| !rest.contains('\\'))
            })
            .cloned()
            .collect())
    }
    pub fn stat(&self, path: &str) -> Option<StatItem> {
        self.metadata.items.get(path).map(|item| StatItem {
            flags: item.flags,
            size: item.size,
        })
    }
    pub fn create(&mut self, path: &str, flags: u32) -> Result<(), Error> {
        if self.metadata.items.contains_key(path) {
            return Err(anyhow::anyhow!("Item already exists"));
        }
        self.metadata.items.insert(
            path.to_string(),
            ItemMetadata {
                flags,
                size: 0,
                blocks: RangeSet::default(),
            },
        );
        self.save_metadata()?;
        Ok(())
    }
    pub fn delete(&mut self, path: &str) -> Result<(), Error> {
        if self
            .metadata
            .items
            .get(path)
            .is_some_and(|item| item.flags & ITEM_FLAG_DIRECTORY != 0)
            && !self.list_dir(path)?.is_empty()
        {
            return Err(anyhow::anyhow!("Directory not empty"));
        }

        let item = self.metadata.items.remove(path).ok_or(NotFoundError)?;
        for block_range in item.blocks.ranges {
            self.metadata.free_ranges.add(block_range);
        }
        self.save_metadata()?;
        Ok(())
    }
    pub fn read(&mut self, path: &str, mut offset: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let item = self.metadata.items.get(path).ok_or(NotFoundError)?;
        if offset + (buffer.len() as u64) > item.size {
            return Err(anyhow::anyhow!("Read out of bounds"));
        }
        let mut buffer_offset = 0;
        for range in &item.blocks.ranges {
            let range_start = range.start * BLOCK_DATA_SIZE as u64;
            let range_end = range.end * BLOCK_DATA_SIZE as u64;
            let range_len = range_end - range_start;
            if buffer_offset as u64 >= buffer.len() as u64 {
                break;
            }
            if offset < range_len {
                let read_len = std::cmp::min(
                    range_len - offset,
                    buffer.len() as u64 - buffer_offset as u64,
                ) as usize;
                self.device.read(
                    range_start + offset,
                    &mut buffer[buffer_offset..buffer_offset + read_len],
                )?;
                buffer_offset += read_len;
                offset = 0;
            } else {
                offset -= range_len;
            }
        }
        Ok(())
    }
    pub fn resize(&mut self, path: &str, new_size: u64) -> Result<(), Error> {
        let item = self.metadata.items.get_mut(path).ok_or(NotFoundError)?;
        let current_blocks = item.blocks.length();
        let required_blocks =
            new_size.next_multiple_of(BLOCK_DATA_SIZE as u64) / BLOCK_DATA_SIZE as u64;
        if required_blocks > current_blocks {
            let additional_blocks = required_blocks - current_blocks;
            let new_ranges = self.metadata.allocate(additional_blocks);

            let item = self.metadata.items.get_mut(path).expect("File exists");
            for range in new_ranges.ranges {
                for i in range.clone() {
                    self.device.write_block(i, vec![0; BLOCK_DATA_SIZE])?;
                }
                item.blocks.add(range);
            }
            item.size = new_size;
        } else if required_blocks < current_blocks {
            let remove_blocks = current_blocks - required_blocks;
            let removed_ranges = item.blocks.shrink(remove_blocks);
            for range in removed_ranges {
                self.metadata.free_ranges.add(range);
            }
            item.size = new_size;
        }

        self.save_metadata()?;
        Ok(())
    }
    pub fn write(&mut self, path: &str, offset: u64, data: &[u8]) -> Result<(), Error> {
        let item = self.metadata.items.get(path).ok_or(NotFoundError)?;
        let required_size = offset + (data.len() as u64);
        if required_size > item.size {
            self.resize(path, required_size)?;
            return self.write(path, offset, data);
        }

        let mut buffer_offset = 0;
        let mut current_offset = offset;
        for range in &item.blocks.ranges {
            let range_start = range.start * BLOCK_DATA_SIZE as u64;
            let range_end = range.end * BLOCK_DATA_SIZE as u64;
            let range_len = range_end - range_start;
            if buffer_offset as u64 >= data.len() as u64 {
                break;
            }
            if current_offset < range_len {
                let write_len = std::cmp::min(
                    range_len - current_offset,
                    data.len() as u64 - buffer_offset as u64,
                ) as usize;
                self.device.write(
                    range_start + current_offset,
                    &data[buffer_offset..buffer_offset + write_len],
                )?;
                buffer_offset += write_len;
                current_offset = 0;
            } else {
                current_offset -= range_len;
            }
        }
        Ok(())
    }
}
