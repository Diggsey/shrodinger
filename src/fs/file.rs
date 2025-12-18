use std::cell::Cell;
use winfsp::filesystem::DirBuffer;
use crate::vfs::FileId;

/// A file context in the encrypted file system.
#[derive(Debug)]
pub struct EncryptedFile {
    file_id: FileId,
    is_directory: bool,
    dir_buffer: DirBuffer,
    delete_on_cleanup: Cell<bool>,
}

impl EncryptedFile {
    pub fn new(file_id: FileId, is_directory: bool) -> Self {
        Self {
            file_id,
            is_directory,
            dir_buffer: DirBuffer::new(),
            delete_on_cleanup: Cell::new(false),
        }
    }

    /// Get the file ID.
    pub fn file_id(&self) -> FileId {
        self.file_id
    }

    /// Whether or not this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Mark for deletion on cleanup.
    pub fn set_delete_on_cleanup(&self, delete: bool) {
        self.delete_on_cleanup.set(delete);
    }

    /// Check if marked for deletion on cleanup.
    pub fn delete_on_cleanup(&self) -> bool {
        self.delete_on_cleanup.get()
    }

    /// Explicitly invalidate the handle before drop.
    pub fn close(self) {
        drop(self)
    }

    /// Get the directory buffer for this file.
    pub fn dir_buffer(&self) -> &DirBuffer {
        &self.dir_buffer
    }
}
