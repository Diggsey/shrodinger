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

pub struct EncryptedBlockDevice {
    backing_file: File,
    offset: u64,
    block_count: i64,
    cipher: Aes256Gcm,
}

const FILE_PREFIX: &[u8] = b"SHRODINGER_V1\0";
const BLOCK_SIZE: u64 = 4096;
const CHECK_DATA: &[u8] = b"SHRODINGER_CHECK";
const CIPHER_TAG: &str = "AES.GCM.V1";
const NONCE_SIZE: usize = <<Aes256Gcm as AeadCore>::NonceSize as Unsigned>::USIZE;
const TAG_SIZE: usize = <<Aes256Gcm as AeadCore>::TagSize as Unsigned>::USIZE;
pub const BLOCK_DATA_SIZE: usize = (BLOCK_SIZE as usize) - NONCE_SIZE - TAG_SIZE;

fn validate_file_prefix(file: &mut File) -> Result<(), anyhow::Error> {
    let mut buffer = [0u8; FILE_PREFIX.len()];
    file.seek(std::io::SeekFrom::Start(0))?;
    file.read_exact(&mut buffer)?;
    if buffer != FILE_PREFIX {
        return Err(anyhow::anyhow!("Invalid backing file format"));
    }
    Ok(())
}

fn read_u64(file: &mut File) -> Result<u64, anyhow::Error> {
    let mut buffer = [0u8; 8];
    file.read_exact(&mut buffer)?;
    Ok(u64::from_le_bytes(buffer))
}

fn write_u64(file: &mut File, value: u64) -> Result<(), anyhow::Error> {
    let buffer = value.to_le_bytes();
    file.write_all(&buffer)?;
    Ok(())
}

fn read_bson<T: serde::de::DeserializeOwned>(file: &mut File) -> Result<T, anyhow::Error> {
    let size = read_u64(file)? as usize;
    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)?;
    Ok(bson::deserialize_from_slice(&mut buffer.as_slice())?)
}

fn write_bson<T: serde::Serialize>(file: &mut File, value: &T) -> Result<(), anyhow::Error> {
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

#[derive(thiserror::Error, Debug)]
#[error("Decryption failed")]
pub struct DecryptionError;

fn decrypt_with_nonce(cipher: &Aes256Gcm, data: &mut impl Buffer) -> Result<(), anyhow::Error> {
    let len = data.len();
    if len < NONCE_SIZE {
        return Err(anyhow::anyhow!("Data too short to contain nonce"));
    }
    let nonce = Nonce::clone_from_slice(&data.as_ref()[(len - NONCE_SIZE)..len]);
    data.truncate(len - NONCE_SIZE);
    cipher
        .decrypt_in_place(&nonce, &[], data)
        .map_err(|_| DecryptionError)?;
    Ok(())
}

fn encrypt_with_nonce(cipher: &Aes256Gcm, data: &mut impl Buffer) -> Result<(), anyhow::Error> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    cipher.encrypt_in_place(&nonce, &[], data)?;
    data.extend_from_slice(&nonce)?;
    Ok(())
}

impl EncryptedBlockDevice {
    pub fn create<'a>(
        mut backing_file: File,
        mut password1: Option<&'a str>,
        mut password2: Option<&'a str>,
    ) -> Result<(), anyhow::Error> {
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
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

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
    pub fn open(mut backing_file: File, password: &str) -> Result<Self, anyhow::Error> {
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

        Err(anyhow::anyhow!("Invalid password"))
    }

    pub fn read_block(&mut self, block_index: u64) -> Result<Vec<u8>, anyhow::Error> {
        let block_offset = self.offset + block_index * BLOCK_SIZE * 2;
        self.backing_file
            .seek(std::io::SeekFrom::Start(block_offset))?;

        let mut encrypted_block = vec![0u8; BLOCK_SIZE as usize];
        self.backing_file.read_exact(&mut encrypted_block)?;

        decrypt_with_nonce(&self.cipher, &mut encrypted_block)?;

        Ok(encrypted_block)
    }

    fn append_random_block(&mut self) -> Result<(), anyhow::Error> {
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
    ) -> Result<(), anyhow::Error> {
        assert_eq!(data.len(), BLOCK_DATA_SIZE);

        let real_block_index = block_index * 2;
        while real_block_index as i64 > self.block_count {
            self.append_random_block()?;
        }

        let block_offset = self.offset + real_block_index * BLOCK_SIZE;
        self.backing_file
            .seek(std::io::SeekFrom::Start(block_offset))?;
        encrypt_with_nonce(&self.cipher, &mut data)?;
        self.backing_file.write_all(&data)?;
        Ok(())
    }

    pub fn read(&mut self, position: u64, buf: &mut [u8]) -> Result<(), anyhow::Error> {
        let mut total_read = 0;
        let mut current_position = position;

        while total_read < buf.len() {
            let block_index = current_position / (BLOCK_DATA_SIZE as u64);
            let block_offset = (current_position % (BLOCK_DATA_SIZE as u64)) as usize;
            let to_read = std::cmp::min(buf.len() - total_read, BLOCK_DATA_SIZE - block_offset);

            if block_index as i64 >= self.block_count {
                return Err(anyhow::anyhow!("Read beyond end of device"));
            }

            let data = self.read_block(block_index)?;
            buf[total_read..total_read + to_read]
                .copy_from_slice(&data[block_offset..block_offset + to_read]);

            total_read += to_read;
            current_position += to_read as u64;
        }

        Ok(())
    }

    pub fn write(&mut self, position: u64, data: &[u8]) -> Result<(), anyhow::Error> {
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
                let mut block_data = self.read_block(block_index).or_else(|e| {
                    if e.is::<DecryptionError>() {
                        Ok(vec![0; BLOCK_DATA_SIZE])
                    } else {
                        Err(e)
                    }
                })?;
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

    pub fn flush(&mut self) -> Result<(), anyhow::Error> {
        self.backing_file.flush()?;
        Ok(())
    }
}
