use crate::fs::file::EncryptedFile;
use std::ffi::OsString;
use std::fs::File;
use std::mem::{offset_of, size_of};

use std::os::raw::c_void;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::ptr::addr_of;
use widestring::{U16CString, u16cstr, u16str};
use windows::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_ID_BOTH_DIR_INFORMATION, FILE_NO_EA_KNOWLEDGE,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE,
    FILE_STREAM_INFORMATION, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT,
    FileIdBothDirectoryInformation, NTCREATEFILE_CREATE_OPTIONS,
};
use windows::Win32::Foundation::{
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, STATUS_ACCESS_DENIED, STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_MEDIA_WRITE_PROTECTED,
    STATUS_NOT_A_DIRECTORY, STATUS_SHARING_VIOLATION,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ACCESS_RIGHTS, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
};
use windows::Win32::System::Ioctl::{
    FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT,
};
use windows::Win32::System::SystemServices::MAXIMUM_ALLOWED;
use windows::core::{HSTRING, PCWSTR};

use winfsp::FspError;
use winfsp::U16CStr;
use winfsp::constants::FspCleanupFlags::FspCleanupDelete;
use winfsp::filesystem::{
    DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, ModificationDescriptor,
    OpenFileInfo, StreamInfo, VolumeInfo, WideNameInfo,
};
use winfsp::host::VolumeParams;
use winfsp::util::{AtomicHandle, Win32HandleDrop};

#[repr(C)]
#[derive(Debug)]
pub struct EncryptedContext {
    backing_file: File,
}

impl EncryptedContext {
    pub fn new(backing_file: File) -> Self {
        Self { backing_file }
    }

    pub fn new_with_volume_params(
        backing_file: File,
        volume_params: &mut VolumeParams,
    ) -> winfsp::Result<Self> {
        volume_params.volume_creation_time(backing_file.metadata()?.creation_time());

        let context = Self::new(backing_file);

        volume_params
            .sector_size(512)
            .sectors_per_allocation_unit(8)
            .max_component_length(255)
            .case_sensitive_search(true)
            .case_preserved_names(true)
            .unicode_on_disk(true)
            .persistent_acls(false)
            .post_cleanup_when_modified_only(true)
            .pass_query_directory_pattern(true)
            .flush_and_purge_on_cleanup(true)
            .wsl_features(true)
            .reparse_points(false)
            .named_streams(false)
            .file_info_timeout(u32::MAX)
            .allow_open_in_kernel_mode(true)
            .supports_posix_unlink_rename(true)
            .post_disposition_only_when_necessary(true);

        Ok(context)
    }
}

impl Drop for EncryptedContext {
    fn drop(&mut self) {
        println!("EncryptedContext was dropped!");
    }
}

impl FileSystemContext for EncryptedContext {
    type FileContext = EncryptedFile;

    fn get_security_by_name(
        &self,
        _file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: FILE_ATTRIBUTE_DIRECTORY.0,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        // Mark as a directory
        {
            file_info.set_normalized_name(file_name.as_slice(), None);
            let fi = file_info.as_mut(); // or equivalent
            fi.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;
            fi.file_size = 0;
            fi.allocation_size = 0;
            // set timestamps if your struct expects them (creation/lastwrite/etc.)
        }
        Ok(Self::FileContext::new(true))
    }

    fn close(&self, context: Self::FileContext) {
        context.close()
    }

    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {}

    fn flush(
        &self,
        _context: Option<&Self::FileContext>,
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.backing_file.sync_all()?;
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if let Ok(dirbuffer) = context.dir_buffer().acquire(marker.is_none(), None) {
            let mut dir_info = DirInfo::<255>::new();
            dir_info.reset();

            dir_info.set_name_raw(u16str!("Hello"))?;

            let file_info = dir_info.file_info_mut();

            file_info.file_attributes = FILE_ATTRIBUTE_DIRECTORY.0;

            dirbuffer.write(&mut dir_info)?;
        }
        Ok(context.dir_buffer().read(marker, buffer))
    }
}
