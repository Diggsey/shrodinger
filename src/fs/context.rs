use crate::block::{BlockDeviceError, EncryptedBlockDevice};
use crate::fs::file::EncryptedFile;
use crate::vfs::{Vfs, VfsError};
use std::fs::File;
use std::sync::{Arc, Mutex};
use tracing::{debug, error, instrument, trace};

use std::os::raw::c_void;
use std::os::windows::fs::MetadataExt;
use std::time::SystemTime;
use windows::Wdk::Storage::FileSystem::FILE_DIRECTORY_FILE;
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL};

use winfsp::FspError;
use winfsp::U16CStr;
use winfsp::constants::FspCleanupFlags::FspCleanupDelete;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo, WideNameInfo,
};
use winfsp::host::VolumeParams;

#[repr(C)]
pub struct EncryptedContext {
    vfs: Arc<Mutex<Vfs>>,
}

/// Convert SystemTime to Windows FILETIME (100-nanosecond intervals since January 1, 1601)
fn system_time_to_filetime(time: SystemTime) -> u64 {
    const UNIX_EPOCH_TO_FILETIME_EPOCH: u64 = 116444736000000000; // 100-nanosecond intervals from 1601 to 1970

    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let intervals =
                duration.as_secs() * 10_000_000 + u64::from(duration.subsec_nanos()) / 100;
            UNIX_EPOCH_TO_FILETIME_EPOCH + intervals
        }
        Err(_) => 0, // Before Unix epoch
    }
}

impl EncryptedContext {
    pub fn new(vfs: Vfs) -> Self {
        Self {
            vfs: Arc::new(Mutex::new(vfs)),
        }
    }

    pub fn new_with_volume_params(
        backing_file: File,
        password: &str,
        volume_params: &mut VolumeParams,
    ) -> winfsp::Result<Self> {
        volume_params.volume_creation_time(backing_file.metadata()?.creation_time());

        // Create encrypted block device and VFS
        let device = EncryptedBlockDevice::open(backing_file, password)?;
        let vfs = Vfs::new(device)?;

        let context = Self::new(vfs);

        volume_params
            .sector_size(512)
            .sectors_per_allocation_unit(8)
            .max_component_length(255)
            .case_sensitive_search(true) // Windows-style case insensitive
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(false)
            .post_cleanup_when_modified_only(true)
            .pass_query_directory_pattern(true)
            .flush_and_purge_on_cleanup(true)
            .wsl_features(false) // Disable for now
            .reparse_points(false)
            .named_streams(false)
            .file_info_timeout(1000)
            .allow_open_in_kernel_mode(true)
            .supports_posix_unlink_rename(false)
            .post_disposition_only_when_necessary(true);

        Ok(context)
    }
}

/// Convert VfsError to WinFSP error codes with logging
impl From<VfsError> for FspError {
    fn from(err: VfsError) -> Self {
        use windows::Win32::Foundation::*;

        match &err {
            VfsError::NotFound => {
                debug!("VFS error: {}", err);
                FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND.0)
            }
            VfsError::FileExists => {
                debug!("VFS error: {}", err);
                FspError::NTSTATUS(STATUS_OBJECT_NAME_COLLISION.0)
            }
            VfsError::DirectoryNotEmpty => {
                debug!("VFS error: {}", err);
                FspError::NTSTATUS(STATUS_DIRECTORY_NOT_EMPTY.0)
            }
            VfsError::CannotDeleteRoot => {
                error!("VFS error: {}", err);
                FspError::NTSTATUS(STATUS_ACCESS_DENIED.0)
            }
            VfsError::ReadOutOfBounds => {
                error!("VFS error: {}", err);
                FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0)
            }
            VfsError::MetadataOverrun { extra_blocks } => {
                error!("VFS error: metadata overrun by {} blocks", extra_blocks);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            VfsError::BlockDevice(e) => {
                error!("VFS block device error: {:?}", e);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            VfsError::Bson(e) => {
                error!("VFS BSON error: {:?}", e);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
        }
    }
}

/// Convert BlockDeviceError to WinFSP error codes with logging
impl From<BlockDeviceError> for FspError {
    fn from(err: BlockDeviceError) -> Self {
        use windows::Win32::Foundation::*;

        match &err {
            BlockDeviceError::InvalidFileFormat => {
                error!("Block device error: {}", err);
                FspError::NTSTATUS(STATUS_INVALID_PARAMETER.0)
            }
            BlockDeviceError::InvalidPassword => {
                error!("Block device error: {}", err);
                FspError::NTSTATUS(STATUS_ACCESS_DENIED.0)
            }
            BlockDeviceError::DataTooShort => {
                error!("Block device error: {}", err);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            BlockDeviceError::DecryptionFailed => {
                error!("Block device error: {}", err);
                FspError::NTSTATUS(STATUS_ACCESS_DENIED.0)
            }
            BlockDeviceError::EncryptionFailed => {
                error!("Block device error: {}", err);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            BlockDeviceError::ReadBeyondEnd => {
                error!("Block device error: {}", err);
                FspError::NTSTATUS(STATUS_END_OF_FILE.0)
            }
            BlockDeviceError::Io(e) => {
                error!("Block device IO error: {:?}", e);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            BlockDeviceError::Bson(e) => {
                error!("Block device BSON error: {:?}", e);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            BlockDeviceError::Argon2PasswordHash(e) => {
                error!("Block device Argon2 password hash error: {:?}", e);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
            BlockDeviceError::Argon2(e) => {
                error!("Block device Argon2 error: {:?}", e);
                FspError::NTSTATUS(STATUS_INTERNAL_ERROR.0)
            }
        }
    }
}

impl Drop for EncryptedContext {
    fn drop(&mut self) {
        println!("EncryptedContext was dropped!");
    }
}

impl FileSystemContext for EncryptedContext {
    type FileContext = EncryptedFile;

    #[instrument(skip(self, _security_descriptor, _resolve_reparse_points))]
    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = file_name.to_string_lossy();
        trace!("get_security_by_name: path={}", path);
        let vfs = self.vfs.lock().unwrap();
        let file_id = vfs.resolve(&path)?;

        // Check if file/directory exists
        let stat = vfs.stat(file_id)?;
        let attributes = if stat.is_directory() {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };

        debug!(
            "get_security_by_name: found path={}, is_dir={}",
            path,
            stat.is_directory()
        );
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes,
        })
    }

    #[instrument(skip(self, _security_descriptor))]
    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = file_name.to_string_lossy();
        let is_directory = (create_options & FILE_DIRECTORY_FILE.0) != 0;
        debug!(
            "create: path={}, is_dir={}, create_options=0x{:x}",
            path, is_directory, create_options
        );

        let mut vfs = self.vfs.lock().unwrap();

        // Split path into parent path and name
        let (parent_path, name) = match path.rfind('\\') {
            Some(pos) if pos > 0 => (&path[..pos], &path[pos + 1..]),
            _ => ("\\", &path[1..]), // Root directory is parent
        };

        // Resolve parent directory
        let parent_id = vfs.resolve(parent_path)?;

        // Determine if creating a directory
        let flags = if is_directory { 0x1 } else { 0 };

        // Create the file or directory
        vfs.create(parent_id, name, flags)?;

        debug!("create: successfully created path={}", path);

        // Resolve the newly created file to get its ID
        let file_id = vfs.resolve(&path)?;

        // Get file info
        let stat = vfs.stat(file_id)?;

        // Get current time for file timestamps
        let now = system_time_to_filetime(SystemTime::now());

        let fi = file_info.as_mut();
        fi.file_attributes = if is_directory {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };
        fi.file_size = stat.size();
        fi.allocation_size = stat.allocation_size();
        fi.creation_time = now;
        fi.last_access_time = now;
        fi.last_write_time = now;
        fi.change_time = now;
        fi.index_number = file_id.as_u64();

        debug!(
            "create: set file_info for path={}, size={}, file_id={:?}, times={}, attrs=0x{:x}",
            path,
            stat.size(),
            file_id,
            now,
            fi.file_attributes
        );

        let file_context = EncryptedFile::new(file_id, is_directory);
        debug!(
            "create: returning file_context successfully for path={}",
            path
        );
        Ok(file_context)
    }

    #[instrument(skip(self))]
    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = file_name.to_string_lossy();
        debug!("open: path={}", path);
        let vfs = self.vfs.lock().unwrap();

        // Resolve path to FileId
        let file_id = vfs.resolve(&path)?;

        // Get file/directory info
        let stat = vfs.stat(file_id)?;

        let is_directory = stat.is_directory();
        debug!(
            "open: found path={}, file_id={:?}, is_dir={}, size={}",
            path,
            file_id,
            is_directory,
            stat.size()
        );

        // Get current time for file timestamps
        let now = system_time_to_filetime(SystemTime::now());

        let fi = file_info.as_mut();
        fi.file_attributes = if is_directory {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };
        fi.file_size = stat.size();
        fi.allocation_size = stat.allocation_size();
        fi.creation_time = now;
        fi.last_access_time = now;
        fi.last_write_time = now;
        fi.change_time = now;
        fi.index_number = file_id.as_u64();

        Ok(EncryptedFile::new(file_id, is_directory))
    }

    #[instrument(skip(self))]
    fn close(&self, context: Self::FileContext) {
        debug!(
            "close: file_id={:?}, delete={}",
            context.file_id(),
            context.delete_on_cleanup()
        );
        // Handle deletion if marked for delete on cleanup
        if context.delete_on_cleanup() {
            let mut vfs = self.vfs.lock().unwrap();
            let _ = vfs.delete(context.file_id());
            debug!("close: deleted file_id={:?}", context.file_id());
        }
        context.close()
    }

    #[instrument(skip(self, buffer))]
    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        trace!(
            "read: file_id={:?}, offset={}, len={}",
            context.file_id(),
            offset,
            buffer.len()
        );
        let mut vfs = self.vfs.lock().unwrap();

        let read_size = vfs.read(context.file_id(), offset, buffer)?;

        debug!(
            "read: success file_id={:?}, offset={}, len={}",
            context.file_id(),
            offset,
            buffer.len()
        );
        Ok(read_size as u32)
    }

    #[instrument(skip(self))]
    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        debug!(
            "write: file_id={:?}, offset={}, len={}",
            context.file_id(),
            offset,
            buffer.len()
        );
        let mut vfs = self.vfs.lock().unwrap();

        // Write data
        vfs.write(context.file_id(), offset, buffer)?;

        // Update file info
        let stat = vfs.stat(context.file_id())?;
        file_info.file_size = stat.size();
        file_info.allocation_size = stat.allocation_size();
        debug!(
            "write: updated file_info file_id={:?}, size={}",
            context.file_id(),
            stat.size()
        );

        debug!(
            "write: success file_id={:?}, offset={}, len={}",
            context.file_id(),
            offset,
            buffer.len()
        );
        Ok(buffer.len() as u32)
    }

    #[instrument(skip(self))]
    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        // Cleanup is handled in set_delete and close
        if FspCleanupDelete.is_flagged(flags) {
            debug!("cleanup: file_id={:?}, delete requested", context.file_id());
            context.set_delete_on_cleanup(true);
        }
    }

    #[instrument(skip(self))]
    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let mut vfs = self.vfs.lock().unwrap();

        // Truncate file to zero
        vfs.resize(context.file_id(), 0)?;

        // Update file info
        file_info.file_size = 0;
        file_info.allocation_size = 0;

        Ok(())
    }

    #[instrument(skip(self))]
    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        debug!("flush: file_id={:?}", context.map(|c| c.file_id()));
        let mut vfs = self.vfs.lock().unwrap();

        // Save VFS metadata
        vfs.save_metadata()?;

        // Update file info if context provided
        if let Some(ctx) = context
            && let Ok(stat) = vfs.stat(ctx.file_id())
        {
            file_info.file_size = stat.size();
            file_info.allocation_size = stat.allocation_size();
            debug!(
                "flush: updated file_info for file_id={:?}, size={}",
                ctx.file_id(),
                stat.size()
            );
        }

        debug!("flush: success");
        Ok(())
    }

    #[instrument(skip(self))]
    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        let vfs = self.vfs.lock().unwrap();

        let stat = vfs.stat(context.file_id())?;

        // Get current time for file timestamps
        let now = system_time_to_filetime(SystemTime::now());

        file_info.file_attributes = if stat.is_directory() {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_NORMAL.0
        };
        file_info.file_size = stat.size();
        file_info.allocation_size = stat.allocation_size();
        file_info.creation_time = now;
        file_info.last_access_time = now;
        file_info.last_write_time = now;
        file_info.change_time = now;
        file_info.index_number = context.file_id().as_u64();

        Ok(())
    }

    #[instrument(skip(self))]
    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if delete_file {
            let vfs = self.vfs.lock().unwrap();

            // Check if it's a non-empty directory
            if context.is_directory() {
                let mut items = vfs.list(context.file_id())?;

                if items.next().is_some() {
                    return Err(FspError::NTSTATUS(
                        windows::Win32::Foundation::STATUS_DIRECTORY_NOT_EMPTY.0,
                    ));
                }
            }

            context.set_delete_on_cleanup(true);
        } else {
            context.set_delete_on_cleanup(false);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    fn rename(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        // Rename not yet implemented - would need VFS support
        Err(FspError::NTSTATUS(
            windows::Win32::Foundation::STATUS_NOT_IMPLEMENTED.0,
        ))
    }

    #[instrument(skip(self, buffer))]
    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        trace!(
            "read_directory: file_id={:?}, marker={:?}",
            context.file_id(),
            marker
        );
        let vfs = self.vfs.lock().unwrap();

        // Populate directory buffer if this is the first read
        if marker.is_none()
            && let Ok(dirbuffer) = context.dir_buffer().acquire(true, None)
        {
            debug!(
                "read_directory: populating buffer for file_id={:?}",
                context.file_id()
            );
            // Add "." and ".." entries
            let mut dir_info = DirInfo::<255>::new();

            // List directory contents
            let items = vfs.list(context.file_id())?;

            let items_vec: Vec<_> = items.collect();
            debug!(
                "read_directory: found {} items in file_id={:?}",
                items_vec.len(),
                context.file_id()
            );

            for (name, stat) in items_vec {
                debug!(
                    "read_directory: adding item={}, is_dir={}",
                    name,
                    stat.is_directory()
                );
                dir_info.reset();

                // Convert to UTF-16
                let filename_wide: Vec<u16> = name.encode_utf16().collect();
                dir_info.set_name_raw(widestring::U16Str::from_slice(&filename_wide))?;

                let fi = dir_info.file_info_mut();
                fi.file_attributes = if stat.is_directory() {
                    FILE_ATTRIBUTE_DIRECTORY.0
                } else {
                    FILE_ATTRIBUTE_NORMAL.0
                };
                fi.file_size = stat.size();
                fi.allocation_size = stat.allocation_size();

                dirbuffer.write(&mut dir_info)?;
            }
        }

        let bytes_read = context.dir_buffer().read(marker, buffer);
        trace!(
            "read_directory: returning {} bytes for file_id={:?}",
            bytes_read,
            context.file_id()
        );
        Ok(bytes_read)
    }
}
