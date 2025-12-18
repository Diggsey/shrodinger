use std::{collections::HashMap, ops::Range};

use anyhow::Error;
use serde::{Deserialize, Serialize};

use crate::block::{BLOCK_DATA_SIZE, DecryptionError, EncryptedBlockDevice};
use crate::range::{RangeSet, SortedRangeSet};

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
    // If reading fails for any reason (new device, corrupted data, etc.), return default metadata
    read_metadata_inner(device).or_else(|_| Ok(VfsMetadata::default()))
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
        let mut metadata = read_metadata(&mut device)?;

        let mut vfs = Self { device, metadata };

        // Initialize metadata blocks if this is a fresh device
        if vfs.metadata.metadata_blocks == 0 {
            vfs.save_metadata()?;
        }

        Ok(vfs)
    }
    pub fn save_metadata(&mut self) -> Result<(), Error> {
        while let Some(err) = write_metadata(&mut self.device, &self.metadata).map_or_else(
            |e| e.downcast::<MetadataOverrunError>().map(Some),
            |()| Ok(None),
        )? {
            let relocations = self.metadata.steal_blocks(
                self.metadata.allocated_blocks..(self.metadata.allocated_blocks + err.extra_blocks),
            );
            self.metadata.metadata_blocks += err.extra_blocks;
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
        } else if required_blocks < current_blocks {
            let remove_blocks = current_blocks - required_blocks;
            let removed_ranges = item.blocks.shrink(remove_blocks);
            for range in removed_ranges {
                self.metadata.free_ranges.add(range);
            }
        }

        // Always update size, even if blocks didn't change
        let item = self.metadata.items.get_mut(path).expect("File exists");
        item.size = new_size;

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

        // VFS should be empty initially
        assert!(vfs.stat("any_path").is_none());
    }

    #[test]
    fn test_create_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create a file
        vfs.create("test.txt", 0).unwrap();

        // File should exist with size 0
        let stat = vfs.stat("test.txt").unwrap();
        assert_eq!(stat.flags, 0);
        assert_eq!(stat.size, 0);
    }

    #[test]
    fn test_create_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create a directory
        vfs.create("mydir", ITEM_FLAG_DIRECTORY).unwrap();

        // Directory should exist
        let stat = vfs.stat("mydir").unwrap();
        assert_eq!(stat.flags, ITEM_FLAG_DIRECTORY);
        assert_eq!(stat.size, 0);
    }

    #[test]
    fn test_create_duplicate() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("test.txt", 0).unwrap();

        // Creating duplicate should fail
        let result = vfs.create("test.txt", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_and_read() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();

        // Write data
        let data = b"Hello, VFS!";
        vfs.write("file.txt", 0, data).unwrap();

        // Verify size increased
        let stat = vfs.stat("file.txt").unwrap();
        assert_eq!(stat.size, data.len() as u64);

        // Read back
        let mut buffer = vec![0u8; data.len()];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer, data);
    }

    #[test]
    fn test_write_at_offset() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();

        // Write initial data
        vfs.write("file.txt", 0, b"AAAA").unwrap();

        // Write at offset
        vfs.write("file.txt", 2, b"BB").unwrap();

        // Read back
        let mut buffer = vec![0u8; 4];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"AABB");
    }

    #[test]
    fn test_write_extends_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();

        // Write beyond current size
        vfs.write("file.txt", 10, b"DATA").unwrap();

        let stat = vfs.stat("file.txt").unwrap();
        assert_eq!(stat.size, 14); // 10 + 4

        // Read back (including zero-filled gap)
        let mut buffer = vec![0u8; 14];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer[0..10], &[0u8; 10]);
        assert_eq!(&buffer[10..14], b"DATA");
    }

    #[test]
    fn test_write_large_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("large.bin", 0).unwrap();

        // Write data larger than one block
        let data = vec![0x42; BLOCK_DATA_SIZE * 3];
        vfs.write("large.bin", 0, &data).unwrap();

        let stat = vfs.stat("large.bin").unwrap();
        assert_eq!(stat.size, data.len() as u64);

        // Read back
        let mut buffer = vec![0u8; data.len()];
        vfs.read("large.bin", 0, &mut buffer).unwrap();
        assert_eq!(buffer, data);
    }

    #[test]
    fn test_resize_grow() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();
        vfs.write("file.txt", 0, b"Hi").unwrap();

        // Grow file
        vfs.resize("file.txt", 100).unwrap();

        let stat = vfs.stat("file.txt").unwrap();
        assert_eq!(stat.size, 100);

        // Original data should still be there
        let mut buffer = vec![0u8; 2];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Hi");
    }

    #[test]
    fn test_resize_shrink() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();
        vfs.write("file.txt", 0, b"Hello, World!").unwrap();

        // Shrink file
        vfs.resize("file.txt", 5).unwrap();

        let stat = vfs.stat("file.txt").unwrap();
        assert_eq!(stat.size, 5);

        // Should only read 5 bytes
        let mut buffer = vec![0u8; 5];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Hello");
    }

    #[test]
    fn test_delete_file() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("temp.txt", 0).unwrap();
        vfs.write("temp.txt", 0, b"data").unwrap();

        // Delete file
        vfs.delete("temp.txt").unwrap();

        // File should no longer exist
        assert!(vfs.stat("temp.txt").is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Deleting nonexistent file should fail
        let result = vfs.delete("nonexistent.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_empty_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("emptydir", ITEM_FLAG_DIRECTORY).unwrap();

        // Should be able to delete empty directory
        vfs.delete("emptydir").unwrap();
        assert!(vfs.stat("emptydir").is_none());
    }

    #[test]
    fn test_delete_nonempty_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("dir", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("dir\\file.txt", 0).unwrap();

        // Should not be able to delete non-empty directory
        let result = vfs.delete("dir");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_dir() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("root", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("root\\file1.txt", 0).unwrap();
        vfs.create("root\\file2.txt", 0).unwrap();
        vfs.create("root\\subdir", ITEM_FLAG_DIRECTORY).unwrap();

        let mut items = vfs.list_dir("root").unwrap();
        items.sort();

        assert_eq!(items.len(), 3);
        assert_eq!(items[0], "root\\file1.txt");
        assert_eq!(items[1], "root\\file2.txt");
        assert_eq!(items[2], "root\\subdir");
    }

    #[test]
    fn test_list_dir_nested() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("a", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("a\\b", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("a\\b\\file.txt", 0).unwrap();
        vfs.create("a\\other.txt", 0).unwrap();

        // List root directory "a"
        let mut items = vfs.list_dir("a").unwrap();
        items.sort();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], "a\\b");
        assert_eq!(items[1], "a\\other.txt");

        // List subdirectory "a\\b"
        let items = vfs.list_dir("a\\b").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "a\\b\\file.txt");
    }

    #[test]
    fn test_list_dir_not_directory() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();

        // Listing a file should fail
        let result = vfs.list_dir("file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_nonexistent() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        let mut buffer = vec![0u8; 10];
        let result = vfs.read("nonexistent.txt", 0, &mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_out_of_bounds() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();
        vfs.write("file.txt", 0, b"Hello").unwrap();

        // Try to read beyond file size
        let mut buffer = vec![0u8; 10];
        let result = vfs.read("file.txt", 0, &mut buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_nonexistent() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Writing to nonexistent file should fail
        let result = vfs.write("nonexistent.txt", 0, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_stat_nonexistent() {
        let (_temp_file, vfs) = create_temp_vfs();

        assert!(vfs.stat("nonexistent.txt").is_none());
    }

    #[test]
    fn test_multiple_files() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create multiple files with different data
        for i in 0..5 {
            let filename = format!("file{}.txt", i);
            vfs.create(&filename, 0).unwrap();

            let data = vec![i as u8; 100];
            vfs.write(&filename, 0, &data).unwrap();
        }

        // Verify all files
        for i in 0..5 {
            let filename = format!("file{}.txt", i);
            let stat = vfs.stat(&filename).unwrap();
            assert_eq!(stat.size, 100);

            let mut buffer = vec![0u8; 100];
            vfs.read(&filename, 0, &mut buffer).unwrap();
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

            vfs.create("persistent.txt", 0).unwrap();
            vfs.write("persistent.txt", 0, b"Persistent data").unwrap();
        }

        // Reopen and verify
        {
            let file = File::options().read(true).write(true).open(&path).unwrap();
            let device = EncryptedBlockDevice::open(file, "persist").unwrap();
            let mut vfs = Vfs::new(device).unwrap();

            let stat = vfs.stat("persistent.txt").unwrap();
            assert_eq!(stat.size, 15);

            let mut buffer = vec![0u8; 15];
            vfs.read("persistent.txt", 0, &mut buffer).unwrap();
            assert_eq!(&buffer, b"Persistent data");
        }
    }

    #[test]
    fn test_overwrite_data() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();
        vfs.write("file.txt", 0, b"Original").unwrap();

        // Overwrite with different data
        vfs.write("file.txt", 0, b"Modified").unwrap();

        let mut buffer = vec![0u8; 8];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"Modified");
    }

    #[test]
    fn test_partial_read() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();
        vfs.write("file.txt", 0, b"0123456789").unwrap();

        // Read from middle
        let mut buffer = vec![0u8; 3];
        vfs.read("file.txt", 5, &mut buffer).unwrap();
        assert_eq!(&buffer, b"567");
    }

    #[test]
    fn test_fragmented_writes() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();

        // Write data in fragments
        vfs.write("file.txt", 0, b"AAA").unwrap();
        vfs.write("file.txt", 3, b"BBB").unwrap();
        vfs.write("file.txt", 6, b"CCC").unwrap();

        let mut buffer = vec![0u8; 9];
        vfs.read("file.txt", 0, &mut buffer).unwrap();
        assert_eq!(&buffer, b"AAABBBCCC");
    }

    #[test]
    fn test_directory_hierarchy() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        // Create directory structure
        vfs.create("root", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("root\\subdir1", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("root\\subdir2", ITEM_FLAG_DIRECTORY).unwrap();
        vfs.create("root\\subdir1\\file.txt", 0).unwrap();

        // Verify structure
        let mut items = vfs.list_dir("root").unwrap();
        items.sort();
        assert_eq!(items.len(), 2);
        assert!(items.contains(&"root\\subdir1".to_string()));
        assert!(items.contains(&"root\\subdir2".to_string()));

        let items = vfs.list_dir("root\\subdir1").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0], "root\\subdir1\\file.txt");
    }

    #[test]
    fn test_resize_to_zero() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();
        vfs.write("file.txt", 0, b"Some data").unwrap();

        // Resize to zero
        vfs.resize("file.txt", 0).unwrap();

        let stat = vfs.stat("file.txt").unwrap();
        assert_eq!(stat.size, 0);
    }

    #[test]
    fn test_empty_write() {
        let (_temp_file, mut vfs) = create_temp_vfs();

        vfs.create("file.txt", 0).unwrap();

        // Write empty data should succeed but not change size
        vfs.write("file.txt", 0, b"").unwrap();

        let stat = vfs.stat("file.txt").unwrap();
        assert_eq!(stat.size, 0);
    }
}
