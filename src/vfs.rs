use std::collections::HashMap;
use std::collections::btree_map::Entry;
use std::time::SystemTime;
use std::{collections::BTreeMap, ops::Range};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::block::{BLOCK_DATA_SIZE, BLOCK_SIZE, BlockDeviceError, EncryptedBlockDevice};
use crate::range::{RangeSet, SortedRangeSet};

fn now() -> u64 {
    const UNIX_EPOCH_TO_FILETIME_EPOCH: u64 = 116444736000000000; // 100-nanosecond intervals from 1601 to 1970

    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let intervals =
                duration.as_secs() * 10_000_000 + u64::from(duration.subsec_nanos()) / 100;
            UNIX_EPOCH_TO_FILETIME_EPOCH + intervals
        }
        Err(_) => 0, // Before Unix epoch
    }
}

pub struct Vfs {
    device: EncryptedBlockDevice,
    metadata: VfsMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId(u64);

impl FileId {
    pub const ROOT: Self = FileId(0);

    /// Get the raw file ID value
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

/// VFS error types
#[derive(Error, Debug)]
pub enum VfsError {
    #[error("Path not found")]
    NotFound,

    #[error("File already exists")]
    FileExists,

    #[error("Directory not empty")]
    DirectoryNotEmpty,

    #[error("Cannot delete root directory")]
    CannotDeleteRoot,

    #[error("Read out of bounds")]
    ReadOutOfBounds,

    #[error("Metadata overrun by {extra_blocks} blocks")]
    MetadataOverrun { extra_blocks: u64 },

    #[error("Block device error: {0}")]
    BlockDevice(#[from] BlockDeviceError),

    #[error("BSON error: {0}")]
    Bson(#[from] bson::error::Error),
}

// Custom serialization module for HashMap<FileId, ItemMetadata>
mod items_serde {
    use super::*;

    pub fn serialize<S>(
        items: &HashMap<FileId, ItemMetadata>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec: Vec<_> = items.iter().map(|(k, v)| (*k, v)).collect();
        vec.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<FileId, ItemMetadata>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<(FileId, ItemMetadata)> = Vec::deserialize(deserializer)?;
        Ok(vec.into_iter().collect())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct VfsMetadata {
    metadata_blocks: u64,
    allocated_blocks: u64,
    #[serde(with = "items_serde")]
    items: HashMap<FileId, ItemMetadata>,
    last_file_id: FileId,
    free_ranges: SortedRangeSet,
}

impl Default for VfsMetadata {
    fn default() -> Self {
        VfsMetadata {
            metadata_blocks: 0,
            allocated_blocks: 0,
            items: HashMap::from([(FileId::ROOT, ItemMetadata::new(None, ITEM_FLAG_DIRECTORY))]),
            free_ranges: SortedRangeSet::default(),
            last_file_id: FileId::ROOT,
        }
    }
}

struct RelocatedBlock {
    old_index: u64,
    new_index: u64,
}

impl VfsMetadata {
    fn allocate_file_id(&mut self) -> FileId {
        self.last_file_id.0 += 1;
        self.last_file_id
    }
    fn allocate(&mut self, count: u64) -> RangeSet {
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
            for (_, item) in self.items.iter_mut() {
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

const ITEM_FLAG_DIRECTORY: u32 = 0x1;

#[derive(Serialize, Deserialize, Debug)]
struct ItemMetadata {
    flags: u32,
    size: u64,
    parent_id: Option<FileId>,
    // For files
    blocks: RangeSet,
    // For directories
    children: BTreeMap<String, FileId>,
    creation_time: u64,
    last_modified_time: u64,
}

impl ItemMetadata {
    fn new(parent_id: Option<FileId>, flags: u32) -> Self {
        Self {
            flags,
            size: 0,
            blocks: RangeSet::default(),
            children: BTreeMap::new(),
            parent_id,
            creation_time: now(),
            last_modified_time: now(),
        }
    }
    fn mark_modified(&mut self) {
        self.last_modified_time = now();
    }
}

pub struct StatItem {
    file_id: FileId,
    flags: u32,
    size: u64,
    allocation_size: u64,
    creation_time: u64,
    last_modified_time: u64,
}

impl StatItem {
    pub fn file_id(&self) -> FileId {
        self.file_id
    }
    pub fn is_directory(&self) -> bool {
        self.flags & ITEM_FLAG_DIRECTORY != 0
    }
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn allocation_size(&self) -> u64 {
        self.allocation_size
    }
    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }
    pub fn last_modified_time(&self) -> u64 {
        self.last_modified_time
    }
}

fn read_metadata(device: &mut EncryptedBlockDevice) -> Result<VfsMetadata, VfsError> {
    fn read_metadata_inner(device: &mut EncryptedBlockDevice) -> Result<VfsMetadata, VfsError> {
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
    // If reading fails for any reason (new device, corrupted data, etc.), return default metadata
    read_metadata_inner(device).or_else(|_| Ok(VfsMetadata::default()))
}

fn write_metadata(device: &mut EncryptedBlockDevice, value: &VfsMetadata) -> Result<(), VfsError> {
    let mut buffer = bson::serialize_to_vec(value)?;
    buffer.extend(u64::to_le_bytes(buffer.len() as u64));
    buffer.rotate_right(8);
    buffer.resize(buffer.len().next_multiple_of(BLOCK_DATA_SIZE), 0);

    let num_blocks = (buffer.len() / BLOCK_DATA_SIZE) as u64;
    if num_blocks > value.metadata_blocks {
        return Err(VfsError::MetadataOverrun {
            extra_blocks: num_blocks - value.metadata_blocks,
        });
    }

    device.write(0, &buffer)?;
    Ok(())
}

impl Vfs {
    pub fn new(mut device: EncryptedBlockDevice) -> Result<Self, VfsError> {
        let metadata = read_metadata(&mut device)?;

        let mut vfs = Self { device, metadata };

        // Initialize metadata blocks if this is a fresh device
        if vfs.metadata.metadata_blocks == 0 {
            vfs.save_metadata()?;
        }

        Ok(vfs)
    }
    pub fn total_size(&self) -> u64 {
        self.metadata.allocated_blocks * BLOCK_DATA_SIZE as u64
    }
    pub fn free_size(&self) -> u64 {
        self.metadata.free_ranges.length() * BLOCK_DATA_SIZE as u64
    }
    pub fn save_metadata(&mut self) -> Result<(), VfsError> {
        loop {
            match write_metadata(&mut self.device, &self.metadata) {
                Ok(()) => break,
                Err(VfsError::MetadataOverrun { extra_blocks }) => {
                    let relocations = self.metadata.steal_blocks(
                        self.metadata.metadata_blocks
                            ..(self.metadata.metadata_blocks + extra_blocks),
                    );
                    self.metadata.metadata_blocks += extra_blocks;
                    for relocation in relocations {
                        let block_data = self.device.read_block(relocation.old_index)?;
                        self.device.write_block(relocation.new_index, block_data)?;
                    }
                }
                Err(e) => return Err(e),
            }
        }
        self.device.flush()?;
        Ok(())
    }
    pub fn resolve(&self, path: &str) -> Result<FileId, VfsError> {
        let mut file_id = FileId::ROOT;
        for segment in path.split('\\').filter(|s| !s.is_empty() && *s != ".") {
            let item = self
                .metadata
                .items
                .get(&file_id)
                .ok_or(VfsError::NotFound)?;
            if item.flags & ITEM_FLAG_DIRECTORY == 0 {
                return Err(VfsError::NotFound);
            }
            if segment == ".." {
                file_id = item.parent_id.ok_or(VfsError::NotFound)?;
                continue;
            }
            file_id = *item.children.get(segment).ok_or(VfsError::NotFound)?;
        }
        Ok(file_id)
    }
    pub fn list(
        &self,
        file_id: FileId,
    ) -> Result<impl Iterator<Item = (&str, StatItem)>, VfsError> {
        let item = self
            .metadata
            .items
            .get(&file_id)
            .ok_or(VfsError::NotFound)?;
        if item.flags & ITEM_FLAG_DIRECTORY == 0 {
            return Err(VfsError::NotFound);
        }
        Ok(item
            .children
            .iter()
            .map(|(name, &file_id)| (name.as_str(), self.stat(file_id).expect("File to exist"))))
    }
    pub fn stat(&self, file_id: FileId) -> Result<StatItem, VfsError> {
        self.metadata
            .items
            .get(&file_id)
            .map(|item| StatItem {
                file_id,
                flags: item.flags,
                size: item.size,
                allocation_size: item.blocks.length() * BLOCK_SIZE,
                creation_time: item.creation_time,
                last_modified_time: item.last_modified_time,
            })
            .ok_or(VfsError::NotFound)
    }
    pub fn create(
        &mut self,
        parent_id: FileId,
        name: &str,
        is_directory: bool,
    ) -> Result<FileId, VfsError> {
        let file_id = self.metadata.allocate_file_id();
        let parent_item = self
            .metadata
            .items
            .get_mut(&parent_id)
            .ok_or(VfsError::NotFound)?;
        match parent_item.children.entry(name.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(file_id);
            }
            Entry::Occupied(_) => {
                return Err(VfsError::FileExists);
            }
        }
        self.metadata.items.insert(
            file_id,
            ItemMetadata::new(
                Some(parent_id),
                if is_directory { ITEM_FLAG_DIRECTORY } else { 0 },
            ),
        );
        self.save_metadata()?;
        Ok(file_id)
    }
    pub fn delete(&mut self, file_id: FileId) -> Result<(), VfsError> {
        if file_id == FileId::ROOT {
            return Err(VfsError::CannotDeleteRoot);
        }
        let item = self
            .metadata
            .items
            .get(&file_id)
            .ok_or(VfsError::NotFound)?;
        if item.flags & ITEM_FLAG_DIRECTORY != 0 && !item.children.is_empty() {
            return Err(VfsError::DirectoryNotEmpty);
        }

        // Unlink from parent
        let parent_id = item.parent_id.ok_or(VfsError::NotFound)?;
        self.metadata
            .items
            .get_mut(&parent_id)
            .ok_or(VfsError::NotFound)?
            .children
            .retain(|_, &mut id| id != file_id);

        // Free blocks
        let item = self
            .metadata
            .items
            .remove(&file_id)
            .ok_or(VfsError::NotFound)?;
        for block_range in item.blocks.ranges {
            self.metadata.free_ranges.add(block_range);
        }
        self.save_metadata()?;
        Ok(())
    }
    pub fn read(
        &mut self,
        file_id: FileId,
        mut offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, VfsError> {
        let item = self
            .metadata
            .items
            .get(&file_id)
            .ok_or(VfsError::NotFound)?;
        let mut read_size = buffer.len() as u64;
        if offset > item.size {
            return Err(VfsError::ReadOutOfBounds);
        }
        if offset + read_size > item.size {
            read_size = item.size - offset;
        }
        let mut buffer_offset = 0;
        for range in &item.blocks.ranges {
            let range_start = range.start * BLOCK_DATA_SIZE as u64;
            let range_end = range.end * BLOCK_DATA_SIZE as u64;
            let range_len = range_end - range_start;
            if buffer_offset as u64 >= read_size {
                break;
            }
            if offset < range_len {
                let read_len =
                    std::cmp::min(range_len - offset, read_size - buffer_offset as u64) as usize;
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
        Ok(read_size as usize)
    }
    pub fn resize(&mut self, file_id: FileId, new_size: u64) -> Result<(), VfsError> {
        let item = self
            .metadata
            .items
            .get_mut(&file_id)
            .ok_or(VfsError::NotFound)?;

        if item.size == new_size {
            return Ok(());
        }

        let current_blocks = item.blocks.length();
        let required_blocks =
            new_size.next_multiple_of(BLOCK_DATA_SIZE as u64) / BLOCK_DATA_SIZE as u64;
        if required_blocks > current_blocks {
            let additional_blocks = required_blocks - current_blocks;
            let new_ranges = self.metadata.allocate(additional_blocks);

            let item = self.metadata.items.get_mut(&file_id).expect("File exists");
            for range in new_ranges.ranges {
                for i in range.clone() {
                    self.device.write_block(i, vec![0; BLOCK_DATA_SIZE])?;
                }
                item.blocks.add(range);
            }
        } else if required_blocks < current_blocks {
            let remove_blocks = current_blocks - required_blocks;
            let removed_ranges = item.blocks.shrink(remove_blocks);
            for range in removed_ranges {
                self.metadata.free_ranges.add(range);
            }
        }

        // Always update size, even if blocks didn't change
        let item = self.metadata.items.get_mut(&file_id).expect("File exists");
        item.size = new_size;
        item.mark_modified();

        self.save_metadata()?;
        Ok(())
    }
    pub fn write(&mut self, file_id: FileId, offset: u64, data: &[u8]) -> Result<(), VfsError> {
        let item = self
            .metadata
            .items
            .get_mut(&file_id)
            .ok_or(VfsError::NotFound)?;
        let required_size = offset + (data.len() as u64);
        if required_size > item.size {
            self.resize(file_id, required_size)?;
            return self.write(file_id, offset, data);
        }

        item.mark_modified();

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

    pub fn rename(
        &mut self,
        file_id: FileId,
        new_parent_id: Option<FileId>,
        new_name: &str,
    ) -> Result<(), VfsError> {
        let item = self
            .metadata
            .items
            .get(&file_id)
            .ok_or(VfsError::NotFound)?;

        // Remove from old parent
        let old_parent_id = item.parent_id.ok_or(VfsError::NotFound)?;
        let new_parent_id = new_parent_id.unwrap_or(old_parent_id);

        // Add to new parent
        let new_parent_item = self
            .metadata
            .items
            .get_mut(&new_parent_id)
            .ok_or(VfsError::NotFound)?;
        if let Some(existing_id) = new_parent_item.children.get(new_name) {
            if existing_id == &file_id {
                // Renaming to same name in same directory; no-op
                return Ok(());
            }
            return Err(VfsError::FileExists);
        }

        // Remove from old parent
        self.metadata
            .items
            .get_mut(&old_parent_id)
            .ok_or(VfsError::NotFound)?
            .children
            .retain(|_, &mut id| id != file_id);

        // Insert into new parent
        let new_parent_item = self
            .metadata
            .items
            .get_mut(&new_parent_id)
            .ok_or(VfsError::NotFound)?;
        new_parent_item
            .children
            .insert(new_name.to_string(), file_id);

        // Update item's parent ID
        let item = self
            .metadata
            .items
            .get_mut(&file_id)
            .ok_or(VfsError::NotFound)?;
        item.parent_id = Some(new_parent_id);

        self.save_metadata()?;
        Ok(())
    }

    pub fn set_metadata(
        &mut self,
        file_id: FileId,
        creation_time: u64,
        last_modified_time: u64,
    ) -> Result<(), VfsError> {
        let item = self
            .metadata
            .items
            .get_mut(&file_id)
            .ok_or(VfsError::NotFound)?;

        if creation_time != 0 {
            item.creation_time = creation_time;
        }
        if last_modified_time != 0 {
            item.last_modified_time = last_modified_time;
        }

        self.save_metadata()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::EncryptedBlockDevice;
    use std::fs::File;
    use tempfile::NamedTempFile;

    fn create_temp_vfs() -> (NamedTempFile, Vfs) {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create encrypted device
        {
            let file = File::create(&path).unwrap();
            EncryptedBlockDevice::create(file, Some("test_password"), None).unwrap();
        }

        // Open device and create VFS
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let device = EncryptedBlockDevice::open(file, "test_password").unwrap();
        let vfs = Vfs::new(device).unwrap();

        (temp_file, vfs)
    }

    #[test]
    fn test_new_vfs() {
        let (_temp_file, vfs) = create_temp_vfs();

        // VFS should have root directory
        let root_stat = vfs.stat(FileId::ROOT).unwrap();
        assert!(root_stat.is_directory());
    }

    #[test]
    fn test_create_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create a file in root
        vfs.create(FileId::ROOT, "test.txt", false).unwrap();

        // File should exist with size 0
        let file_id = vfs.resolve("\\test.txt").unwrap();
        let stat = vfs.stat(file_id).unwrap();
        assert!(!stat.is_directory());
        assert_eq!(stat.size(), 0);
    }

    #[test]
    fn test_create_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create a directory in root
        vfs.create(FileId::ROOT, "mydir", true).unwrap();

        // Directory should exist
        let dir_id = vfs.resolve("\\mydir").unwrap();
        let stat = vfs.stat(dir_id).unwrap();
        assert!(stat.is_directory());
        assert_eq!(stat.size(), 0);
    }

    #[test]
    fn test_create_duplicate() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "test.txt", false).unwrap();

        // Creating duplicate should fail
        let result = vfs.create(FileId::ROOT, "test.txt", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_and_read() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();

        // Write data
        let data = b"Hello, VFS!";
        vfs.write(file_id, 0, data).unwrap();

        // Verify size increased
        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), data.len() as u64);

        // Read back
        let mut buffer = vec![0u8; data.len()];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, data);
    }

    #[test]
    fn test_write_at_offset() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();

        // Write initial data
        vfs.write(file_id, 0, b"AAAA").unwrap();

        // Write at offset
        vfs.write(file_id, 2, b"BB").unwrap();

        // Read back
        let mut buffer = vec![0u8; 4];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"AABB");
    }

    #[test]
    fn test_write_extends_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();

        // Write beyond current size
        vfs.write(file_id, 10, b"DATA").unwrap();

        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), 14); // 10 + 4

        // Read back (including zero-filled gap)
        let mut buffer = vec![0u8; 14];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer[0..10], &[0u8; 10]);
        assert_eq!(&buffer[10..14], b"DATA");
    }

    #[test]
    fn test_write_large_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "large.bin", false).unwrap();
        let file_id = vfs.resolve("\\large.bin").unwrap();

        // Write data larger than one block
        let data = vec![0x42; BLOCK_DATA_SIZE * 3];
        vfs.write(file_id, 0, &data).unwrap();

        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), data.len() as u64);

        // Read back
        let mut buffer = vec![0u8; data.len()];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(buffer, data);
    }

    #[test]
    fn test_resize_grow() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();
        vfs.write(file_id, 0, b"Hi").unwrap();

        // Grow file
        vfs.resize(file_id, 100).unwrap();

        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), 100);

        // Original data should still be there
        let mut buffer = vec![0u8; 2];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Hi");
    }

    #[test]
    fn test_resize_shrink() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();
        vfs.write(file_id, 0, b"Hello, World!").unwrap();

        // Shrink file
        vfs.resize(file_id, 5).unwrap();

        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), 5);

        // Should only read 5 bytes
        let mut buffer = vec![0u8; 5];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Hello");
    }

    #[test]
    fn test_delete_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "temp.txt", false).unwrap();
        let file_id = vfs.resolve("\\temp.txt").unwrap();
        vfs.write(file_id, 0, b"data").unwrap();

        // Delete file
        vfs.delete(file_id).unwrap();

        // File should no longer exist
        assert!(vfs.resolve("\\temp.txt").is_err());
    }

    #[test]
    fn test_delete_nonexistent() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Deleting nonexistent file should fail
        let result = vfs.delete(FileId(9999));
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_empty_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "emptydir", true).unwrap();
        let dir_id = vfs.resolve("\\emptydir").unwrap();

        // Should be able to delete empty directory
        vfs.delete(dir_id).unwrap();
        assert!(vfs.resolve("\\emptydir").is_err());
    }

    #[test]
    fn test_delete_nonempty_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "dir", true).unwrap();
        let dir_id = vfs.resolve("\\dir").unwrap();
        vfs.create(dir_id, "file.txt", false).unwrap();

        // Should not be able to delete non-empty directory
        let result = vfs.delete(dir_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_dir() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "root", true).unwrap();
        let root_id = vfs.resolve("\\root").unwrap();
        vfs.create(root_id, "file1.txt", false).unwrap();
        vfs.create(root_id, "file2.txt", false).unwrap();
        vfs.create(root_id, "subdir", true).unwrap();

        let mut items: Vec<_> = vfs
            .list(root_id)
            .unwrap()
            .map(|(name, _)| name.to_string())
            .collect();
        items.sort();

        assert_eq!(items.len(), 3);
        assert_eq!(items[0], "file1.txt");
        assert_eq!(items[1], "file2.txt");
        assert_eq!(items[2], "subdir");
    }

    #[test]
    fn test_list_dir_nested() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "a", true).unwrap();
        let a_id = vfs.resolve("\\a").unwrap();
        vfs.create(a_id, "b", true).unwrap();
        let b_id = vfs.resolve("\\a\\b").unwrap();
        vfs.create(b_id, "file.txt", false).unwrap();
        vfs.create(a_id, "other.txt", false).unwrap();

        // List directory "a"
        let mut items: Vec<_> = vfs
            .list(a_id)
            .unwrap()
            .map(|(name, _)| name.to_string())
            .collect();
        items.sort();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], "b");
        assert_eq!(items[1], "other.txt");

        // List subdirectory "a\\b"
        let items: Vec<_> = vfs
            .list(b_id)
            .unwrap()
            .map(|(name, _)| name.to_string())
            .collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "file.txt");
    }

    #[test]
    fn test_list_dir_not_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();

        // Listing a file should fail
        let result = vfs.list(file_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_nonexistent() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        let mut buffer = vec![0u8; 10];
        let result = vfs.read(FileId(9999), 0, &mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_out_of_bounds() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();
        vfs.write(file_id, 0, b"Hello").unwrap();

        // Try to read beyond file size
        let mut buffer = vec![0u8; 10];
        let result = vfs.read(file_id, 0, &mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_nonexistent() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Writing to nonexistent file should fail
        let result = vfs.write(FileId(9999), 0, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_stat_nonexistent() {
        let (_temp_file, vfs) = create_temp_vfs();

        assert!(vfs.stat(FileId(9999)).is_err());
    }

    #[test]
    fn test_multiple_files() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create multiple files with different data
        let mut file_ids = Vec::new();
        for i in 0..5 {
            let filename = format!("file{}.txt", i);
            vfs.create(FileId::ROOT, &filename, false).unwrap();
            let file_id = vfs.resolve(&format!("\\{}", filename)).unwrap();
            file_ids.push(file_id);

            let data = vec![i as u8; 100];
            vfs.write(file_id, 0, &data).unwrap();
        }

        // Verify all files
        for (i, &file_id) in file_ids.iter().enumerate() {
            let stat = vfs.stat(file_id).unwrap();
            assert_eq!(stat.size(), 100);

            let mut buffer = vec![0u8; 100];
            vfs.read(file_id, 0, &mut buffer).unwrap();
            assert_eq!(buffer, vec![i as u8; 100]);
        }
    }

    #[test]
    fn test_persistence() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create VFS and write data
        {
            let file = File::create(&path).unwrap();
            EncryptedBlockDevice::create(file, Some("persist"), None).unwrap();

            let file = File::options().read(true).write(true).open(&path).unwrap();
            let device = EncryptedBlockDevice::open(file, "persist").unwrap();
            let mut vfs = Vfs::new(device).unwrap();

            vfs.create(FileId::ROOT, "persistent.txt", false).unwrap();
            let file_id = vfs.resolve("\\persistent.txt").unwrap();
            vfs.write(file_id, 0, b"Persistent data").unwrap();
        }

        // Reopen and verify
        {
            let file = File::options().read(true).write(true).open(&path).unwrap();
            let device = EncryptedBlockDevice::open(file, "persist").unwrap();
            let mut vfs = Vfs::new(device).unwrap();

            let file_id = vfs.resolve("\\persistent.txt").unwrap();
            let stat = vfs.stat(file_id).unwrap();
            assert_eq!(stat.size(), 15);

            let mut buffer = vec![0u8; 15];
            vfs.read(file_id, 0, &mut buffer).unwrap();
            assert_eq!(&buffer, b"Persistent data");
        }
    }

    #[test]
    fn test_overwrite_data() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();
        vfs.write(file_id, 0, b"Original").unwrap();

        // Overwrite with different data
        vfs.write(file_id, 0, b"Modified").unwrap();

        let mut buffer = vec![0u8; 8];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Modified");
    }

    #[test]
    fn test_partial_read() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();
        vfs.write(file_id, 0, b"0123456789").unwrap();

        // Read from middle
        let mut buffer = vec![0u8; 3];
        vfs.read(file_id, 5, &mut buffer).unwrap();
        assert_eq!(&buffer, b"567");
    }

    #[test]
    fn test_fragmented_writes() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();

        // Write data in fragments
        vfs.write(file_id, 0, b"AAA").unwrap();
        vfs.write(file_id, 3, b"BBB").unwrap();
        vfs.write(file_id, 6, b"CCC").unwrap();

        let mut buffer = vec![0u8; 9];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"AAABBBCCC");
    }

    #[test]
    fn test_directory_hierarchy() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create directory structure
        vfs.create(FileId::ROOT, "root", true).unwrap();
        let root_id = vfs.resolve("\\root").unwrap();
        vfs.create(root_id, "subdir1", true).unwrap();
        vfs.create(root_id, "subdir2", true).unwrap();
        let subdir1_id = vfs.resolve("\\root\\subdir1").unwrap();
        vfs.create(subdir1_id, "file.txt", false).unwrap();

        // Verify structure
        let mut items: Vec<_> = vfs
            .list(root_id)
            .unwrap()
            .map(|(name, _)| name.to_string())
            .collect();
        items.sort();
        assert_eq!(items.len(), 2);
        assert!(items.contains(&"subdir1".to_string()));
        assert!(items.contains(&"subdir2".to_string()));

        let items: Vec<_> = vfs
            .list(subdir1_id)
            .unwrap()
            .map(|(name, _)| name.to_string())
            .collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "file.txt");
    }

    #[test]
    fn test_resize_to_zero() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();
        vfs.write(file_id, 0, b"Some data").unwrap();

        // Resize to zero
        vfs.resize(file_id, 0).unwrap();

        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), 0);
    }

    #[test]
    fn test_empty_write() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        let file_id = vfs.resolve("\\file.txt").unwrap();

        // Write empty data should succeed but not change size
        vfs.write(file_id, 0, b"").unwrap();

        let stat = vfs.stat(file_id).unwrap();
        assert_eq!(stat.size(), 0);
    }

    #[test]
    fn test_metadata_growth() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        let file_id = vfs.create(FileId::ROOT, "file.txt", false).unwrap();
        vfs.write(file_id, 0, b"Important data").unwrap();

        // Force metadata to grow into space allocated to the important file
        for i in 0..100 {
            let temp_id = vfs
                .create(FileId::ROOT, &format!("tempfile-{i}.txt"), false)
                .unwrap();
            vfs.write(temp_id, 0, b"Filler data").unwrap();
        }

        let mut buffer = [0u8; 14];
        vfs.read(file_id, 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Important data");
    }
}
