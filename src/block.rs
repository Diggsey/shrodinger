use std::{
    fs::File,
    io::{Read as _, Seek as _, Write as _},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit as _, Nonce,
    aead::{AeadInPlace, Buffer, OsRng, rand_core::RngCore as _},
    aes::cipher::Unsigned,
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub struct EncryptedBlockDevice {
    backing_file: File,
    offset: u64,
    block_count: i64,
    cipher: Aes256Gcm,
}

const FILE_PREFIX: &[u8] = b"SHRODINGER_V1\0";
pub const BLOCK_SIZE: u64 = 4096;
const CHECK_DATA: &[u8] = b"SHRODINGER_CHECK";
const NONCE_SIZE: usize = <<Aes256Gcm as AeadCore>::NonceSize as Unsigned>::USIZE;
const TAG_SIZE: usize = <<Aes256Gcm as AeadCore>::TagSize as Unsigned>::USIZE;
pub const BLOCK_DATA_SIZE: usize = (BLOCK_SIZE as usize) - NONCE_SIZE - TAG_SIZE;

fn validate_file_prefix(file: &mut File) -> Result<(), BlockDeviceError> {
    let mut buffer = [0u8; FILE_PREFIX.len()];
    file.seek(std::io::SeekFrom::Start(0))?;
    file.read_exact(&mut buffer)?;
    if buffer != FILE_PREFIX {
        return Err(BlockDeviceError::InvalidFileFormat);
    }
    Ok(())
}

fn read_u64(file: &mut File) -> Result<u64, BlockDeviceError> {
    let mut buffer = [0u8; 8];
    file.read_exact(&mut buffer)?;
    Ok(u64::from_le_bytes(buffer))
}

fn write_u64(file: &mut File, value: u64) -> Result<(), BlockDeviceError> {
    let buffer = value.to_le_bytes();
    file.write_all(&buffer)?;
    Ok(())
}

fn read_bson<T: serde::de::DeserializeOwned>(file: &mut File) -> Result<T, BlockDeviceError> {
    let size = read_u64(file)? as usize;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)?;
    Ok(bson::deserialize_from_slice(buffer.as_slice())?)
}

fn write_bson<T: serde::Serialize>(file: &mut File, value: &T) -> Result<(), BlockDeviceError> {
    let buffer = bson::serialize_to_vec(value)?;
    write_u64(file, buffer.len() as u64)?;
    file.write_all(&buffer)?;
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct Metadata {
    sides: [SideMetadata; 2],
}

#[derive(Deserialize, Serialize, Debug)]
struct SideMetadata {
    salt: Vec<u8>,
    check: Vec<u8>,
}

/// Block device error types
#[derive(Error, Debug)]
pub enum BlockDeviceError {
    #[error("Invalid backing file format")]
    InvalidFileFormat,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Data too short to contain nonce")]
    DataTooShort,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Read beyond end of device")]
    ReadBeyondEnd,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("BSON error: {0}")]
    Bson(#[from] bson::error::Error),

    #[error("Argon2 password hash error: {0}")]
    Argon2PasswordHash(#[from] argon2::password_hash::Error),

    #[error("Argon2 error: {0}")]
    Argon2(#[from] argon2::Error),
}

fn decrypt_with_nonce(cipher: &Aes256Gcm, data: &mut impl Buffer) -> Result<(), BlockDeviceError> {
    let len = data.len();
    if len < NONCE_SIZE {
        return Err(BlockDeviceError::DataTooShort);
    }
    let nonce = Nonce::clone_from_slice(&data.as_ref()[(len - NONCE_SIZE)..len]);
    data.truncate(len - NONCE_SIZE);
    cipher
        .decrypt_in_place(&nonce, &[], data)
        .map_err(|_| BlockDeviceError::DecryptionFailed)?;
    Ok(())
}

fn encrypt_with_nonce(cipher: &Aes256Gcm, data: &mut impl Buffer) -> Result<(), BlockDeviceError> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher
        .encrypt_in_place(&nonce, &[], data)
        .map_err(|_| BlockDeviceError::EncryptionFailed)?;
    data.extend_from_slice(&nonce)
        .map_err(|_| BlockDeviceError::EncryptionFailed)?;
    Ok(())
}

impl EncryptedBlockDevice {
    pub fn create<'a>(
        mut backing_file: File,
        mut password1: Option<&'a str>,
        mut password2: Option<&'a str>,
    ) -> Result<(), BlockDeviceError> {
        let file_size = backing_file.metadata()?.len();
        assert_eq!(file_size, 0);

        // Randomize the password order
        if OsRng.next_u32().is_multiple_of(2) {
            std::mem::swap(&mut password1, &mut password2);
        }

        backing_file.seek(std::io::SeekFrom::Start(0))?;
        backing_file.write_all(FILE_PREFIX)?;

        // Initialize metadata
        let sides = (0..2)
            .map(|i| {
                let password = if i == 0 { password1 } else { password2 };
                let mut salt = [0u8; 16];
                OsRng.fill_bytes(&mut salt);
                let mut key = Key::<Aes256Gcm>::default();
                if let Some(pw) = password {
                    Argon2::default().hash_password_into(pw.as_bytes(), &salt, &mut key)?;
                } else {
                    // If no password is provided, use a random key
                    OsRng.fill_bytes(&mut key);
                }
                let cipher = Aes256Gcm::new(&key);

                let mut check_data = CHECK_DATA.to_vec();
                encrypt_with_nonce(&cipher, &mut check_data)?;

                Ok(SideMetadata {
                    salt: salt.to_vec(),
                    check: check_data,
                })
            })
            .collect::<Result<Vec<_>, BlockDeviceError>>()?;

        // Write metadata
        let metadata = Metadata {
            sides: sides.try_into().expect("Should have exactly 2 sides"),
        };
        write_bson(&mut backing_file, &metadata)?;

        let offset = backing_file.stream_position()?.next_multiple_of(BLOCK_SIZE);

        backing_file.set_len(offset)?;
        backing_file.flush()?;

        Ok(())
    }
    pub fn open(mut backing_file: File, password: &str) -> Result<Self, BlockDeviceError> {
        let file_size = backing_file.metadata()?.len();
        validate_file_prefix(&mut backing_file)?;

        let mut metadata: Metadata = read_bson(&mut backing_file)?;
        let offset = backing_file.stream_position()?.next_multiple_of(BLOCK_SIZE);

        for (index, side) in metadata.sides.iter_mut().enumerate() {
            let mut key = Key::<Aes256Gcm>::default();
            Argon2::default().hash_password_into(password.as_bytes(), &side.salt, &mut key)?;
            let cipher = Aes256Gcm::new(&key);
            if decrypt_with_nonce(&cipher, &mut side.check).is_ok() {
                assert_eq!(&side.check, CHECK_DATA);
                let mut this = Self {
                    backing_file,
                    offset: offset + (index as u64) * BLOCK_SIZE,
                    block_count: (file_size as i64 - offset as i64) / BLOCK_SIZE as i64,
                    cipher,
                };
                if this.block_count < 0 {
                    this.append_random_block()?;
                }
                return Ok(this);
            }
        }

        Err(BlockDeviceError::InvalidPassword)
    }

    pub fn read_block(&mut self, block_index: u64) -> Result<Vec<u8>, BlockDeviceError> {
        let block_offset = self.offset + block_index * BLOCK_SIZE * 2;
        self.backing_file
            .seek(std::io::SeekFrom::Start(block_offset))?;

        let mut encrypted_block = vec![0u8; BLOCK_SIZE as usize];
        self.backing_file.read_exact(&mut encrypted_block)?;

        decrypt_with_nonce(&self.cipher, &mut encrypted_block)?;

        Ok(encrypted_block)
    }

    fn append_random_block(&mut self) -> Result<(), BlockDeviceError> {
        self.backing_file.seek(std::io::SeekFrom::End(0))?;
        let mut data = [0u8; BLOCK_SIZE as usize];
        OsRng.fill_bytes(&mut data);
        self.backing_file.write_all(&data)?;
        self.block_count += 1;
        Ok(())
    }

    pub fn write_block(
        &mut self,
        block_index: u64,
        mut data: Vec<u8>,
    ) -> Result<(), BlockDeviceError> {
        assert_eq!(data.len(), BLOCK_DATA_SIZE);

        let real_block_index = block_index * 2;
        while real_block_index as i64 >= self.block_count {
            self.append_random_block()?;
        }

        let block_offset = self.offset + real_block_index * BLOCK_SIZE;
        self.backing_file
            .seek(std::io::SeekFrom::Start(block_offset))?;
        encrypt_with_nonce(&self.cipher, &mut data)?;
        self.backing_file.write_all(&data)?;
        Ok(())
    }

    pub fn read(&mut self, position: u64, buf: &mut [u8]) -> Result<(), BlockDeviceError> {
        let mut total_read = 0;
        let mut current_position = position;

        while total_read < buf.len() {
            let block_index = current_position / (BLOCK_DATA_SIZE as u64);
            let block_offset = (current_position % (BLOCK_DATA_SIZE as u64)) as usize;
            let to_read = std::cmp::min(buf.len() - total_read, BLOCK_DATA_SIZE - block_offset);
            let real_block_index = block_index * 2;

            if real_block_index as i64 >= self.block_count {
                return Err(BlockDeviceError::ReadBeyondEnd);
            }

            let data = self.read_block(block_index)?;
            buf[total_read..total_read + to_read]
                .copy_from_slice(&data[block_offset..block_offset + to_read]);

            total_read += to_read;
            current_position += to_read as u64;
        }

        Ok(())
    }

    pub fn write(&mut self, position: u64, data: &[u8]) -> Result<(), BlockDeviceError> {
        let mut total_written = 0;
        let mut current_position = position;

        while total_written < data.len() {
            let block_index = current_position / (BLOCK_DATA_SIZE as u64);
            let block_offset = (current_position % (BLOCK_DATA_SIZE as u64)) as usize;
            let to_write =
                std::cmp::min(data.len() - total_written, BLOCK_DATA_SIZE - block_offset);

            let block_data = if block_offset == 0 && to_write == BLOCK_DATA_SIZE {
                data[total_written..total_written + to_write].to_vec()
            } else {
                // Try to read existing block, or use zeros if it doesn't exist or can't be decrypted
                let real_block_index = block_index * 2;
                let mut block_data = if (real_block_index as i64) < self.block_count {
                    self.read_block(block_index).or_else(|e| {
                        if matches!(e, BlockDeviceError::DecryptionFailed) {
                            Ok(vec![0; BLOCK_DATA_SIZE])
                        } else {
                            Err(e)
                        }
                    })?
                } else {
                    vec![0; BLOCK_DATA_SIZE]
                };
                block_data[block_offset..block_offset + to_write]
                    .copy_from_slice(&data[total_written..total_written + to_write]);
                block_data
            };
            self.write_block(block_index, block_data)?;

            total_written += to_write;
            current_position += to_write as u64;
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), BlockDeviceError> {
        self.backing_file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_temp_device(password: &str) -> (NamedTempFile, EncryptedBlockDevice) {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create the encrypted device
        {
            let file = File::create(&path).unwrap();
            EncryptedBlockDevice::create(file, Some(password), None).unwrap();
        }

        // Reopen it
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let device = EncryptedBlockDevice::open(file, password).unwrap();

        (temp_file, device)
    }

    fn create_temp_device_dual_password(
        password1: &str,
        password2: &str,
    ) -> (NamedTempFile, EncryptedBlockDevice, EncryptedBlockDevice) {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create the encrypted device with dual passwords
        let file = File::create(&path).unwrap();
        EncryptedBlockDevice::create(file, Some(password1), Some(password2)).unwrap();

        // Open with first password
        let file1 = File::options().read(true).write(true).open(&path).unwrap();
        let device1 = EncryptedBlockDevice::open(file1, password1).unwrap();

        // Open with second password
        let file2 = File::options().read(true).write(true).open(&path).unwrap();
        let device2 = EncryptedBlockDevice::open(file2, password2).unwrap();

        (temp_file, device1, device2)
    }

    #[test]
    fn test_create_and_open() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create a new encrypted device
        let file = File::create(&path).unwrap();
        EncryptedBlockDevice::create(file, Some("test_password"), None).unwrap();

        // Verify file was created with correct prefix
        let mut file = File::open(&path).unwrap();
        let mut prefix = [0u8; FILE_PREFIX.len()];
        file.read_exact(&mut prefix).unwrap();
        assert_eq!(&prefix, FILE_PREFIX);

        // Open with correct password should succeed
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let result = EncryptedBlockDevice::open(file, "test_password");
        assert!(result.is_ok());
    }

    #[test]
    fn test_open_with_wrong_password() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create device
        let file = File::create(&path).unwrap();
        EncryptedBlockDevice::create(file, Some("correct_password"), None).unwrap();

        // Try to open with wrong password
        let file = File::options().read(true).write(true).open(&path).unwrap();
        let result = EncryptedBlockDevice::open(file, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_dual_password() {
        let (_temp_file, mut device1, mut device2) =
            create_temp_device_dual_password("password1", "password2");

        // Write data with first password
        let data1 = vec![0xAA; BLOCK_DATA_SIZE];
        device1.write_block(0, data1.clone()).unwrap();
        device1.flush().unwrap();

        // Write data with second password (different block due to offset)
        let data2 = vec![0xBB; BLOCK_DATA_SIZE];
        device2.write_block(0, data2.clone()).unwrap();
        device2.flush().unwrap();

        // Read back with first password
        let read_data1 = device1.read_block(0).unwrap();
        assert_eq!(read_data1, data1);

        // Read back with second password
        let read_data2 = device2.read_block(0).unwrap();
        assert_eq!(read_data2, data2);

        // Verify they're different
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_write_and_read_block() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write a block
        let data = vec![0x42; BLOCK_DATA_SIZE];
        device.write_block(0, data.clone()).unwrap();

        // Read it back
        let read_data = device.read_block(0).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_write_and_read_multiple_blocks() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write multiple blocks with different data
        for i in 0..5 {
            let data = vec![i as u8; BLOCK_DATA_SIZE];
            device.write_block(i, data).unwrap();
        }

        // Read them back and verify
        for i in 0..5 {
            let read_data = device.read_block(i).unwrap();
            assert_eq!(read_data, vec![i as u8; BLOCK_DATA_SIZE]);
        }
    }

    #[test]
    fn test_overwrite_block() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write initial data
        let data1 = vec![0x11; BLOCK_DATA_SIZE];
        device.write_block(0, data1).unwrap();

        // Overwrite with new data
        let data2 = vec![0x22; BLOCK_DATA_SIZE];
        device.write_block(0, data2.clone()).unwrap();

        // Read back should return new data
        let read_data = device.read_block(0).unwrap();
        assert_eq!(read_data, data2);
    }

    #[test]
    fn test_read_write_at_position() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write some data at position 0
        let data = b"Hello, World!";
        device.write(0, data).unwrap();
        device.flush().unwrap();

        // Read it back
        let mut read_data = vec![0u8; data.len()];
        device.read(0, &mut read_data).unwrap();
        assert_eq!(&read_data, data);
    }

    #[test]
    fn test_read_write_across_blocks() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write data that spans multiple blocks
        let data = vec![0x55; BLOCK_DATA_SIZE * 2 + 100];
        device.write(0, &data).unwrap();

        // Read it back
        let mut read_data = vec![0u8; data.len()];
        device.read(0, &mut read_data).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_write_at_offset() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write initial data
        let initial_data = vec![0x00; BLOCK_DATA_SIZE];
        device.write(0, &initial_data).unwrap();

        // Write at an offset
        let offset = 100;
        let write_data = b"INSERTED DATA";
        device.write(offset, write_data).unwrap();

        // Read back the whole block
        let mut read_data = vec![0u8; BLOCK_DATA_SIZE];
        device.read(0, &mut read_data).unwrap();

        // Verify the data was inserted at the correct position
        assert_eq!(
            &read_data[offset as usize..offset as usize + write_data.len()],
            write_data
        );
        assert_eq!(read_data[0], 0x00); // Before offset should be unchanged
    }

    #[test]
    fn test_write_partial_block() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write data smaller than a block
        let data = b"Small data";
        device.write(0, data).unwrap();

        // Read it back
        let mut read_data = vec![0u8; data.len()];
        device.read(0, &mut read_data).unwrap();
        assert_eq!(&read_data, data);
    }

    #[test]
    fn test_write_spanning_blocks() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write data that starts in one block and ends in another
        let offset = BLOCK_DATA_SIZE as u64 - 50;
        let data = vec![0x77; 150]; // Spans across block boundary
        device.write(offset, &data).unwrap();

        // Read it back
        let mut read_data = vec![0u8; data.len()];
        device.read(offset, &mut read_data).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_block_data_size_constant() {
        // Verify BLOCK_DATA_SIZE calculation is correct
        assert_eq!(
            BLOCK_DATA_SIZE,
            (BLOCK_SIZE as usize) - NONCE_SIZE - TAG_SIZE
        );
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(BLOCK_DATA_SIZE, 4068);
    }

    #[test]
    fn test_persistence() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create and write data
        {
            let file = File::create(&path).unwrap();
            EncryptedBlockDevice::create(file, Some("persist_test"), None).unwrap();

            let file = File::options().read(true).write(true).open(&path).unwrap();
            let mut device = EncryptedBlockDevice::open(file, "persist_test").unwrap();

            let data = b"Persistent data";
            device.write(0, data).unwrap();
            device.flush().unwrap();
        }

        // Reopen and verify data persisted
        {
            let file = File::options().read(true).write(true).open(&path).unwrap();
            let mut device = EncryptedBlockDevice::open(file, "persist_test").unwrap();

            let mut read_data = vec![0u8; 15];
            device.read(0, &mut read_data).unwrap();
            assert_eq!(&read_data, b"Persistent data");
        }
    }

    #[test]
    fn test_large_write() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write a large amount of data
        let data = vec![0xCC; BLOCK_DATA_SIZE * 10];
        device.write(0, &data).unwrap();

        // Read it back
        let mut read_data = vec![0u8; data.len()];
        device.read(0, &mut read_data).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_different_data_patterns() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Test with different data patterns
        let patterns = [
            vec![0x00; 1000],                                        // All zeros
            vec![0xFF; 1000],                                        // All ones
            (0..1000).map(|i| (i % 256) as u8).collect::<Vec<u8>>(), // Sequential
            [0xAA, 0x55].repeat(500),                                // Alternating pattern
        ];

        for (i, pattern) in patterns.iter().enumerate() {
            let offset = (i * 2000) as u64;
            device.write(offset, pattern).unwrap();

            let mut read_data = vec![0u8; pattern.len()];
            device.read(offset, &mut read_data).unwrap();
            assert_eq!(&read_data, pattern);
        }
    }

    #[test]
    fn test_flush() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        let data = b"Test flush";
        device.write(0, data).unwrap();

        // Flush should succeed
        assert!(device.flush().is_ok());
    }

    #[test]
    fn test_non_sequential_block_writes() {
        let (_temp_file, mut device) = create_temp_device("test_password");

        // Write blocks in non-sequential order
        let data_block_5 = vec![5u8; BLOCK_DATA_SIZE];
        let data_block_2 = vec![2u8; BLOCK_DATA_SIZE];
        let data_block_8 = vec![8u8; BLOCK_DATA_SIZE];

        device.write_block(5, data_block_5.clone()).unwrap();
        device.write_block(2, data_block_2.clone()).unwrap();
        device.write_block(8, data_block_8.clone()).unwrap();

        // Read them back
        assert_eq!(device.read_block(5).unwrap(), data_block_5);
        assert_eq!(device.read_block(2).unwrap(), data_block_2);
        assert_eq!(device.read_block(8).unwrap(), data_block_8);
    }

    #[test]
    fn test_create_with_no_password() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_owned();

        // Create with no password (uses random key)
        let file = File::create(&path).unwrap();
        let result = EncryptedBlockDevice::create(file, None, None);

        // Should succeed
        assert!(result.is_ok());
    }
}
