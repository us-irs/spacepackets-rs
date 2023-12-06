//! Generic CFDP type-length-value (TLV) abstraction as specified in CFDP 5.1.9.
use crate::cfdp::lv::{
    generic_len_check_data_serialization, generic_len_check_deserialization, Lv, MIN_LV_LEN,
};
use crate::cfdp::TlvLvError;
use crate::util::{UnsignedByteField, UnsignedByteFieldError, UnsignedEnum};
use crate::ByteConversionError;
#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use num_enum::{IntoPrimitive, TryFromPrimitive};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod msg_to_user;

pub const MIN_TLV_LEN: usize = 2;

pub trait GenericTlv {
    fn tlv_type_field(&self) -> TlvTypeField;

    /// Checks whether the type field contains one of the standard types specified in the CFDP
    /// standard and is part of the [TlvType] enum.
    fn is_standard_tlv(&self) -> bool {
        if let TlvTypeField::Standard(_) = self.tlv_type_field() {
            return true;
        }
        false
    }

    /// Returns the standard TLV type if the TLV field is not a custom field
    fn tlv_type(&self) -> Option<TlvType> {
        if let TlvTypeField::Standard(tlv_type) = self.tlv_type_field() {
            Some(tlv_type)
        } else {
            None
        }
    }
}

pub trait WritableTlv {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError>;
    fn len_written(&self) -> usize;
    #[cfg(feautre = "alloc")]
    fn to_vec(&self) -> Vec<u8> {
        let mut buf = vec![0; self.len_written()];
        self.write_to_bytes(&mut buf).unwrap();
        buf
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum TlvType {
    FilestoreRequest = 0x00,
    FilestoreResponse = 0x01,
    MsgToUser = 0x02,
    FaultHandler = 0x04,
    FlowLabel = 0x05,
    EntityId = 0x06,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TlvTypeField {
    Standard(TlvType),
    Custom(u8),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum FilestoreActionCode {
    CreateFile = 0b0000,
    DeleteFile = 0b0001,
    RenameFile = 0b0010,
    /// This operation appends one file to another. The first specified name will form the first
    /// part of the new file and the name of the new file. This function can be used to get
    /// similar functionality to the UNIX cat utility (albeit for only two files).
    AppendFile = 0b0011,
    /// This operation replaces the content of the first specified file with the content of
    /// the secondly specified file.
    ReplaceFile = 0b0100,
    CreateDirectory = 0b0101,
    RemoveDirectory = 0b0110,
    DenyFile = 0b0111,
    DenyDirectory = 0b1000,
}

impl From<u8> for TlvTypeField {
    fn from(value: u8) -> Self {
        match TlvType::try_from(value) {
            Ok(tlv_type) => TlvTypeField::Standard(tlv_type),
            Err(_) => TlvTypeField::Custom(value),
        }
    }
}

impl From<TlvTypeField> for u8 {
    fn from(value: TlvTypeField) -> Self {
        match value {
            TlvTypeField::Standard(std) => std as u8,
            TlvTypeField::Custom(custom) => custom,
        }
    }
}

/// Generic CFDP type-length-value (TLV) abstraction as specified in CFDP 5.1.9.
///
/// Please note that this class is zero-copy and does not generate a copy of the value data for
/// both the regular [Self::new] constructor and the [Self::from_bytes] constructor.
///
/// # Lifetimes
///  * `data`: If the TLV is generated from a raw bytestream, this will be the lifetime of
///    the raw bytestream. If the TLV is generated from a raw slice or a similar data reference,
///    this will be the lifetime of that data reference.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Tlv<'data> {
    tlv_type_field: TlvTypeField,
    #[cfg_attr(feature = "serde", serde(borrow))]
    lv: Lv<'data>,
}

impl<'data> Tlv<'data> {
    pub fn new(tlv_type: TlvType, data: &[u8]) -> Result<Tlv, TlvLvError> {
        Ok(Tlv {
            tlv_type_field: TlvTypeField::Standard(tlv_type),
            lv: Lv::new(data)?,
        })
    }

    pub fn new_with_custom_type(tlv_type: u8, data: &[u8]) -> Result<Tlv, TlvLvError> {
        Ok(Tlv {
            tlv_type_field: TlvTypeField::Custom(tlv_type),
            lv: Lv::new(data)?,
        })
    }

    /// Creates a TLV with an empty value field.
    pub fn new_empty(tlv_type: TlvType) -> Tlv<'data> {
        Tlv {
            tlv_type_field: TlvTypeField::Standard(tlv_type),
            lv: Lv::new_empty(),
        }
    }

    pub fn value(&self) -> &[u8] {
        self.lv.value()
    }

    /// Checks whether the value field is empty.
    pub fn is_empty(&self) -> bool {
        self.value().is_empty()
    }

    /// Helper method to retrieve the length of the value. Simply calls the [slice::len] method of
    /// [Self::value]
    pub fn len_value(&self) -> usize {
        self.value().len()
    }

    /// Returns the full raw length, including the length byte.
    pub fn len_full(&self) -> usize {
        self.len_value() + 2
    }

    /// Creates a TLV give a raw bytestream. Please note that is is not necessary to pass the
    /// bytestream with the exact size of the expected TLV. This function will take care
    /// of parsing the length byte, and the length of the parsed TLV can be retrieved using
    /// [Self::len_full].
    pub fn from_bytes(buf: &'data [u8]) -> Result<Tlv<'data>, TlvLvError> {
        generic_len_check_deserialization(buf, MIN_TLV_LEN)?;
        let mut tlv = Self {
            tlv_type_field: TlvTypeField::from(buf[0]),
            lv: Lv::from_bytes(&buf[MIN_LV_LEN..])?,
        };
        // We re-use this field so we do not need an additional struct field to store the raw start
        // of the TLV.
        tlv.lv.raw_data = Some(buf);
        Ok(tlv)
    }

    /// If the TLV was generated from a raw bytestream using [Self::from_bytes], the raw start
    /// of the TLV can be retrieved with this method.
    pub fn raw_data(&self) -> Option<&[u8]> {
        self.lv.raw_data()
    }
}

impl WritableTlv for Tlv<'_> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        generic_len_check_data_serialization(buf, self.value().len(), MIN_TLV_LEN)?;
        buf[0] = self.tlv_type_field.into();
        self.lv.write_to_be_bytes_no_len_check(&mut buf[1..]);
        Ok(self.len_full())
    }
    fn len_written(&self) -> usize {
        self.len_full()
    }
}

impl GenericTlv for Tlv<'_> {
    fn tlv_type_field(&self) -> TlvTypeField {
        self.tlv_type_field
    }
}

pub(crate) fn verify_tlv_type(raw_type: u8, expected_tlv_type: TlvType) -> Result<(), TlvLvError> {
    let tlv_type = TlvType::try_from(raw_type).map_err(|_| TlvLvError::InvalidTlvTypeField {
        found: raw_type,
        expected: Some(expected_tlv_type.into()),
    })?;
    if tlv_type != expected_tlv_type {
        return Err(TlvLvError::InvalidTlvTypeField {
            found: tlv_type as u8,
            expected: Some(expected_tlv_type as u8),
        });
    }
    Ok(())
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EntityIdTlv {
    entity_id: UnsignedByteField,
}

impl EntityIdTlv {
    pub fn new(entity_id: UnsignedByteField) -> Self {
        Self { entity_id }
    }

    fn len_check(buf: &[u8]) -> Result<(), ByteConversionError> {
        if buf.len() < 2 {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: 2,
            });
        }
        Ok(())
    }

    pub fn entity_id(&self) -> &UnsignedByteField {
        &self.entity_id
    }

    pub fn len_value(&self) -> usize {
        self.entity_id.size()
    }

    pub fn len_full(&self) -> usize {
        2 + self.entity_id.size()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, TlvLvError> {
        Self::len_check(buf)?;
        verify_tlv_type(buf[0], TlvType::EntityId)?;
        let len = buf[1];
        if len != 1 && len != 2 && len != 4 && len != 8 {
            return Err(TlvLvError::InvalidValueLength(len as usize));
        }
        // Okay to unwrap here. The checks before make sure that the deserialization never fails
        let entity_id = UnsignedByteField::new_from_be_bytes(len as usize, &buf[2..]).unwrap();
        Ok(Self { entity_id })
    }

    /// Convert to a generic [Tlv], which also erases the programmatic type information.
    pub fn to_tlv(self, buf: &mut [u8]) -> Result<Tlv, ByteConversionError> {
        Self::len_check(buf)?;
        self.entity_id
            .write_to_be_bytes(&mut buf[2..2 + self.entity_id.size()])?;
        Tlv::new(TlvType::EntityId, &buf[2..2 + self.entity_id.size()]).map_err(|e| match e {
            TlvLvError::ByteConversion(e) => e,
            // All other errors are impossible.
            _ => panic!("unexpected TLV error"),
        })
    }
}

impl WritableTlv for EntityIdTlv {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        Self::len_check(buf)?;
        buf[0] = TlvType::EntityId as u8;
        buf[1] = self.entity_id.size() as u8;
        Ok(2 + self.entity_id.write_to_be_bytes(&mut buf[2..])?)
    }

    fn len_written(&self) -> usize {
        self.len_full()
    }
}

impl GenericTlv for EntityIdTlv {
    fn tlv_type_field(&self) -> TlvTypeField {
        TlvTypeField::Standard(TlvType::EntityId)
    }
}

impl<'data> TryFrom<Tlv<'data>> for EntityIdTlv {
    type Error = TlvLvError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        match value.tlv_type_field {
            TlvTypeField::Standard(tlv_type) => {
                if tlv_type != TlvType::EntityId {
                    return Err(TlvLvError::InvalidTlvTypeField {
                        found: tlv_type as u8,
                        expected: Some(TlvType::EntityId as u8),
                    });
                }
            }
            TlvTypeField::Custom(val) => {
                return Err(TlvLvError::InvalidTlvTypeField {
                    found: val,
                    expected: Some(TlvType::EntityId as u8),
                });
            }
        }
        let len_value = value.value().len();
        if len_value != 1 && len_value != 2 && len_value != 4 && len_value != 8 {
            return Err(TlvLvError::InvalidValueLength(len_value));
        }
        Ok(Self::new(
            UnsignedByteField::new_from_be_bytes(len_value, value.value()).map_err(
                |e| match e {
                    UnsignedByteFieldError::ByteConversionError(e) => e,
                    // This can not happen, we checked for the length validity, and the data is always smaller than
                    // 255 bytes.
                    _ => panic!("unexpected error"),
                },
            )?,
        ))
    }
}

pub fn fs_request_has_second_filename(action_code: FilestoreActionCode) -> bool {
    if action_code == FilestoreActionCode::RenameFile
        || action_code == FilestoreActionCode::AppendFile
        || action_code == FilestoreActionCode::ReplaceFile
    {
        return true;
    }
    false
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct FilestoreTlvBase<'first_name, 'second_name> {
    pub action_code: FilestoreActionCode,
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub first_name: Lv<'first_name>,
    #[cfg_attr(feature = "serde", serde(borrow))]
    pub second_name: Option<Lv<'second_name>>,
}

impl FilestoreTlvBase<'_, '_> {
    fn base_len_value(&self) -> usize {
        let mut len = 1 + self.first_name.len_full();
        if let Some(second_name) = self.second_name {
            len += second_name.len_full();
        }
        len
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FilestoreRequestTlv<'first_name, 'second_name> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    base: FilestoreTlvBase<'first_name, 'second_name>,
}

impl<'first_name, 'second_name> FilestoreRequestTlv<'first_name, 'second_name> {
    pub fn new_create_file(file_name: Lv<'first_name>) -> Result<Self, TlvLvError> {
        Self::new(FilestoreActionCode::CreateFile, file_name, None)
    }

    pub fn new_delete_file(file_name: Lv<'first_name>) -> Result<Self, TlvLvError> {
        Self::new(FilestoreActionCode::DeleteFile, file_name, None)
    }

    pub fn new_rename_file(
        source_name: Lv<'first_name>,
        target_name: Lv<'second_name>,
    ) -> Result<Self, TlvLvError> {
        Self::new(
            FilestoreActionCode::RenameFile,
            source_name,
            Some(target_name),
        )
    }

    /// This operation appends one file to another. The first specified name will form the first
    /// part of the new file and the name of the new file. This function can be used to get
    /// similar functionality to the UNIX cat utility (albeit for only two files).
    pub fn new_append_file(
        first_file: Lv<'first_name>,
        second_file: Lv<'second_name>,
    ) -> Result<Self, TlvLvError> {
        Self::new(
            FilestoreActionCode::AppendFile,
            first_file,
            Some(second_file),
        )
    }

    /// This operation replaces the content of the first specified file with the content of
    /// the secondly specified file. This function can be used to get similar functionality to
    /// the UNIX copy (cp) utility if the target file already exists.
    pub fn new_replace_file(
        replaced_file: Lv<'first_name>,
        new_file: Lv<'second_name>,
    ) -> Result<Self, TlvLvError> {
        Self::new(
            FilestoreActionCode::ReplaceFile,
            replaced_file,
            Some(new_file),
        )
    }

    pub fn new_create_directory(dir_name: Lv<'first_name>) -> Result<Self, TlvLvError> {
        Self::new(FilestoreActionCode::CreateDirectory, dir_name, None)
    }

    pub fn new_remove_directory(dir_name: Lv<'first_name>) -> Result<Self, TlvLvError> {
        Self::new(FilestoreActionCode::RemoveDirectory, dir_name, None)
    }

    pub fn new_deny_file(file_name: Lv<'first_name>) -> Result<Self, TlvLvError> {
        Self::new(FilestoreActionCode::DenyFile, file_name, None)
    }

    pub fn new_deny_directory(dir_name: Lv<'first_name>) -> Result<Self, TlvLvError> {
        Self::new(FilestoreActionCode::DenyDirectory, dir_name, None)
    }

    /// This function will return [None] if the respective action code requires two names but
    /// only one is passed. It will also returns [None] if the cumulative length of the first
    /// name and the second name exceeds 255 bytes.
    ///
    /// Two file paths are required for the rename, append and replace filestore request.
    pub fn new(
        action_code: FilestoreActionCode,
        first_name: Lv<'first_name>,
        second_name: Option<Lv<'second_name>>,
    ) -> Result<Self, TlvLvError> {
        let mut base_value_len = first_name.len_full();
        if fs_request_has_second_filename(action_code) {
            if second_name.is_none() {
                return Err(TlvLvError::SecondNameMissing);
            }
            base_value_len += second_name.as_ref().unwrap().len_full();
        }
        if base_value_len > u8::MAX as usize {
            return Err(TlvLvError::InvalidValueLength(base_value_len));
        }
        Ok(Self {
            base: FilestoreTlvBase {
                action_code,
                first_name,
                second_name,
            },
        })
    }

    pub fn action_code(&self) -> FilestoreActionCode {
        self.base.action_code
    }

    pub fn first_name(&self) -> Lv<'first_name> {
        self.base.first_name
    }

    pub fn second_name(&self) -> Option<Lv<'second_name>> {
        self.base.second_name
    }

    pub fn len_value(&self) -> usize {
        self.base.base_len_value()
    }

    pub fn len_full(&self) -> usize {
        2 + self.len_value()
    }

    pub fn from_bytes<'longest: 'first_name + 'second_name>(
        buf: &'longest [u8],
    ) -> Result<Self, TlvLvError> {
        if buf.len() < 2 {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 2,
            }
            .into());
        }
        verify_tlv_type(buf[0], TlvType::FilestoreRequest)?;
        let len = buf[1] as usize;
        let mut current_idx = 2;
        let action_code = FilestoreActionCode::try_from((buf[2] >> 4) & 0b1111)
            .map_err(|_| TlvLvError::InvalidFilestoreActionCode((buf[2] >> 4) & 0b1111))?;
        current_idx += 1;
        let first_name = Lv::from_bytes(&buf[current_idx..])?;
        let mut second_name = None;

        current_idx += first_name.len_full();
        if fs_request_has_second_filename(action_code) {
            if current_idx >= 2 + len {
                return Err(TlvLvError::SecondNameMissing);
            }
            second_name = Some(Lv::from_bytes(&buf[current_idx..])?);
        }
        Ok(Self {
            base: FilestoreTlvBase {
                action_code,
                first_name,
                second_name,
            },
        })
    }
}

impl WritableTlv for FilestoreRequestTlv<'_, '_> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.len_full() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.len_full(),
            });
        }
        buf[0] = TlvType::FilestoreRequest as u8;
        buf[1] = self.len_value() as u8;
        buf[2] = (self.base.action_code as u8) << 4;
        let mut current_idx = 3;
        // Length checks were already performed.
        self.base.first_name.write_to_be_bytes_no_len_check(
            &mut buf[current_idx..current_idx + self.base.first_name.len_full()],
        );
        current_idx += self.base.first_name.len_full();
        if let Some(second_name) = self.base.second_name {
            second_name.write_to_be_bytes_no_len_check(
                &mut buf[current_idx..current_idx + second_name.len_full()],
            );
            current_idx += second_name.len_full();
        }
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.len_full()
    }
}

impl GenericTlv for FilestoreRequestTlv<'_, '_> {
    fn tlv_type_field(&self) -> TlvTypeField {
        TlvTypeField::Standard(TlvType::FilestoreRequest)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FilestoreResponseTlv<'first_name, 'second_name, 'fs_msg> {
    #[cfg_attr(feature = "serde", serde(borrow))]
    base: FilestoreTlvBase<'first_name, 'second_name>,
    status_code: u8,
    #[cfg_attr(feature = "serde", serde(borrow))]
    filestore_message: Lv<'fs_msg>,
}

impl<'first_name, 'second_name, 'fs_msg> FilestoreResponseTlv<'first_name, 'second_name, 'fs_msg> {
    /// This function will return [None] if the respective action code requires two names but
    /// only one is passed. It will also returns [None] if the cumulative length of the first
    /// name and the second name exceeds 255 bytes.
    ///
    /// Two file paths are required for the rename, append and replace filestore request.
    pub fn new_no_filestore_message(
        action_code: FilestoreActionCode,
        status_code: u8,
        first_name: Lv<'first_name>,
        second_name: Option<Lv<'second_name>>,
    ) -> Result<Self, TlvLvError> {
        Self::new(
            action_code,
            status_code,
            first_name,
            second_name,
            Lv::new_empty(),
        )
    }
    pub fn new(
        action_code: FilestoreActionCode,
        status_code: u8,
        first_name: Lv<'first_name>,
        second_name: Option<Lv<'second_name>>,
        filestore_message: Lv<'fs_msg>,
    ) -> Result<Self, TlvLvError> {
        let mut base_value_len = first_name.len_full();
        if Self::has_second_filename(action_code) {
            if second_name.is_none() {
                return Err(TlvLvError::SecondNameMissing);
            }
            base_value_len += second_name.as_ref().unwrap().len_full();
        }
        if base_value_len > u8::MAX as usize {
            return Err(TlvLvError::InvalidValueLength(base_value_len));
        }
        Ok(Self {
            base: FilestoreTlvBase {
                action_code,
                first_name,
                second_name,
            },
            status_code,
            filestore_message,
        })
    }

    pub fn has_second_filename(action_code: FilestoreActionCode) -> bool {
        if action_code == FilestoreActionCode::RenameFile
            || action_code == FilestoreActionCode::AppendFile
            || action_code == FilestoreActionCode::ReplaceFile
        {
            return true;
        }
        false
    }

    pub fn action_code(&self) -> FilestoreActionCode {
        self.base.action_code
    }

    pub fn status_code(&self) -> u8 {
        self.status_code
    }

    pub fn first_name(&self) -> Lv<'first_name> {
        self.base.first_name
    }

    pub fn second_name(&self) -> Option<Lv<'second_name>> {
        self.base.second_name
    }

    pub fn len_value(&self) -> usize {
        self.base.base_len_value() + self.filestore_message.len_full()
    }

    pub fn len_full(&self) -> usize {
        2 + self.len_value()
    }

    pub fn from_bytes<'buf: 'first_name + 'second_name + 'fs_msg>(
        buf: &'buf [u8],
    ) -> Result<Self, TlvLvError> {
        if buf.len() < 2 {
            return Err(ByteConversionError::FromSliceTooSmall {
                found: buf.len(),
                expected: 2,
            }
            .into());
        }
        verify_tlv_type(buf[0], TlvType::FilestoreResponse)?;
        let len = buf[1] as usize;
        let mut current_idx = 2;
        let len_check = |current_idx: &mut usize, add_len: usize| -> Result<(), TlvLvError> {
            if *current_idx + add_len > buf.len() {
                return Err(ByteConversionError::FromSliceTooSmall {
                    found: buf.len(),
                    expected: *current_idx,
                }
                .into());
            }
            Ok(())
        };
        len_check(&mut current_idx, len)?;
        let action_code = FilestoreActionCode::try_from((buf[2] >> 4) & 0b1111)
            .map_err(|_| TlvLvError::InvalidFilestoreActionCode((buf[2] >> 4) & 0b1111))?;
        let status_code = buf[2] & 0b1111;
        current_idx += 1;
        let first_name = Lv::from_bytes(&buf[current_idx..])?;
        len_check(&mut current_idx, first_name.len_full())?;
        current_idx += first_name.len_full();

        let mut second_name = None;
        if Self::has_second_filename(action_code) {
            if current_idx >= 2 + len {
                return Err(TlvLvError::SecondNameMissing);
            }
            let second_name_lv = Lv::from_bytes(&buf[current_idx..])?;
            current_idx += second_name_lv.len_full();
            second_name = Some(second_name_lv);
        }
        let filestore_message = Lv::from_bytes(&buf[current_idx..])?;
        len_check(&mut current_idx, filestore_message.len_full())?;
        Ok(Self {
            base: FilestoreTlvBase {
                action_code,
                first_name,
                second_name,
            },
            status_code,
            filestore_message,
        })
    }
}

impl WritableTlv for FilestoreResponseTlv<'_, '_, '_> {
    fn write_to_bytes(&self, buf: &mut [u8]) -> Result<usize, ByteConversionError> {
        if buf.len() < self.len_full() {
            return Err(ByteConversionError::ToSliceTooSmall {
                found: buf.len(),
                expected: self.len_full(),
            });
        }
        buf[0] = TlvType::FilestoreResponse as u8;
        buf[1] = self.len_value() as u8;
        buf[2] = ((self.base.action_code as u8) << 4) | (self.status_code & 0b1111);
        let mut current_idx = 3;
        // Length checks were already performed.
        self.base.first_name.write_to_be_bytes_no_len_check(
            &mut buf[current_idx..current_idx + self.base.first_name.len_full()],
        );
        current_idx += self.base.first_name.len_full();
        if let Some(second_name) = self.base.second_name {
            current_idx += second_name.write_to_be_bytes_no_len_check(
                &mut buf[current_idx..current_idx + second_name.len_full()],
            );
        }
        current_idx += self.filestore_message.write_to_be_bytes_no_len_check(
            &mut buf[current_idx..current_idx + self.filestore_message.len_full()],
        );
        Ok(current_idx)
    }

    fn len_written(&self) -> usize {
        self.len_full()
    }
}

impl GenericTlv for FilestoreResponseTlv<'_, '_, '_> {
    fn tlv_type_field(&self) -> TlvTypeField {
        TlvTypeField::Standard(TlvType::FilestoreResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfdp::lv::Lv;
    use crate::cfdp::tlv::{FilestoreActionCode, FilestoreRequestTlv, Tlv, TlvType, TlvTypeField};
    use crate::cfdp::TlvLvError;
    use crate::util::{UbfU16, UbfU8, UnsignedEnum};
    use alloc::string::ToString;

    const TLV_TEST_STR_0: &str = "hello.txt";
    const TLV_TEST_STR_1: &str = "hello2.txt";

    #[test]
    fn test_basic() {
        let entity_id = UbfU8::new(5);
        let mut buf: [u8; 4] = [0; 4];
        assert!(entity_id.write_to_be_bytes(&mut buf).is_ok());
        let tlv_res = Tlv::new(TlvType::EntityId, &buf[0..1]);
        assert!(tlv_res.is_ok());
        let tlv_res = tlv_res.unwrap();
        assert_eq!(
            tlv_res.tlv_type_field(),
            TlvTypeField::Standard(TlvType::EntityId)
        );
        assert_eq!(tlv_res.len_full(), 3);
        assert_eq!(tlv_res.value().len(), 1);
        assert_eq!(tlv_res.len_value(), 1);
        assert!(!tlv_res.is_empty());
        assert_eq!(tlv_res.value()[0], 5);
    }

    #[test]
    fn test_serialization() {
        let entity_id = UbfU8::new(5);
        let mut buf: [u8; 4] = [0; 4];
        assert!(entity_id.write_to_be_bytes(&mut buf).is_ok());
        let tlv_res = Tlv::new(TlvType::EntityId, &buf[0..1]);
        assert!(tlv_res.is_ok());
        let tlv_res = tlv_res.unwrap();
        let mut ser_buf: [u8; 4] = [0; 4];
        assert!(tlv_res.write_to_bytes(&mut ser_buf).is_ok());
        assert_eq!(ser_buf[0], TlvType::EntityId as u8);
        assert_eq!(ser_buf[1], 1);
        assert_eq!(ser_buf[2], 5);
    }

    #[test]
    fn test_deserialization() {
        let entity_id = UbfU8::new(5);
        let mut buf: [u8; 4] = [0; 4];
        assert!(entity_id.write_to_be_bytes(&mut buf[2..]).is_ok());
        buf[0] = TlvType::EntityId as u8;
        buf[1] = 1;
        let tlv_from_raw = Tlv::from_bytes(&buf);
        assert!(tlv_from_raw.is_ok());
        let tlv_from_raw = tlv_from_raw.unwrap();
        assert!(tlv_from_raw.raw_data().is_some());
        assert_eq!(tlv_from_raw.raw_data().unwrap(), buf);
        assert_eq!(
            tlv_from_raw.tlv_type_field(),
            TlvTypeField::Standard(TlvType::EntityId)
        );
        assert_eq!(tlv_from_raw.value().len(), 1);
        assert_eq!(tlv_from_raw.len_full(), 3);
        assert_eq!(tlv_from_raw.value()[0], 5);
    }

    #[test]
    fn test_entity_id_tlv() {
        let entity_id = UbfU16::new(0x0102);
        let entity_id_tlv = EntityIdTlv::new(entity_id.into());
        let mut buf: [u8; 16] = [0; 16];
        let written_len = entity_id_tlv.write_to_bytes(&mut buf).unwrap();
        assert_eq!(written_len, entity_id_tlv.len_full());
        assert_eq!(entity_id_tlv.len_value(), 2);
        assert!(entity_id_tlv.is_standard_tlv());
        assert_eq!(entity_id_tlv.tlv_type().unwrap(), TlvType::EntityId);
        assert_eq!(buf[0], TlvType::EntityId as u8);
        assert_eq!(buf[1], 2);
        assert_eq!(u16::from_be_bytes(buf[2..4].try_into().unwrap()), 0x0102);
        let entity_id_as_vec = entity_id_tlv.to_vec();
        assert_eq!(entity_id_as_vec, buf[0..written_len].to_vec());
    }

    #[test]
    fn test_entity_id_from_generic_tlv() {
        let entity_id = UbfU16::new(0x0102);
        let entity_id_tlv = EntityIdTlv::new(entity_id.into());
        let mut buf: [u8; 16] = [0; 16];
        let entity_id_as_tlv: Tlv = entity_id_tlv.to_tlv(&mut buf).unwrap();
        let entity_id_converted_back: EntityIdTlv = entity_id_as_tlv.try_into().unwrap();
        assert_eq!(entity_id_converted_back, entity_id_tlv);
    }

    #[test]
    fn test_entity_id_from_raw() {
        let entity_id = UbfU16::new(0x0102);
        let entity_id_tlv = EntityIdTlv::new(entity_id.into());
        let mut buf: [u8; 16] = [0; 16];
        let _ = entity_id_tlv.write_to_bytes(&mut buf).unwrap();
        let entity_tlv_from_raw =
            EntityIdTlv::from_bytes(&buf).expect("creating entity ID TLV failed");
        assert_eq!(entity_tlv_from_raw, entity_id_tlv);
        assert_eq!(entity_tlv_from_raw.entity_id(), &entity_id.into());
    }

    #[test]
    fn test_empty() {
        let tlv_empty = Tlv::new_empty(TlvType::MsgToUser);
        assert_eq!(tlv_empty.value().len(), 0);
        assert!(tlv_empty.is_empty());
        assert_eq!(tlv_empty.len_full(), 2);
        assert!(tlv_empty.value().is_empty());
        assert_eq!(
            tlv_empty.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );
    }

    #[test]
    fn test_empty_serialization() {
        let tlv_empty = Tlv::new_empty(TlvType::MsgToUser);
        let mut buf: [u8; 4] = [0; 4];
        assert!(tlv_empty.write_to_bytes(&mut buf).is_ok());
        assert_eq!(buf[0], TlvType::MsgToUser as u8);
        assert_eq!(buf[1], 0);
    }

    #[test]
    fn test_empty_deserialization() {
        let mut buf: [u8; 4] = [0; 4];
        buf[0] = TlvType::MsgToUser as u8;
        buf[1] = 0;
        let tlv_empty = Tlv::from_bytes(&buf);
        assert!(tlv_empty.is_ok());
        let tlv_empty = tlv_empty.unwrap();
        assert!(tlv_empty.is_empty());
        assert_eq!(tlv_empty.value().len(), 0);
        assert_eq!(
            tlv_empty.tlv_type_field(),
            TlvTypeField::Standard(TlvType::MsgToUser)
        );
        assert_eq!(tlv_empty.len_full(), 2);
        assert!(tlv_empty.value().is_empty());
    }

    #[test]
    fn test_write_buf_too_small() {
        let mut buf: [u8; 2] = [0; 2];
        let fs_request =
            FilestoreRequestTlv::new_create_file(Lv::new_from_str(TLV_TEST_STR_0).unwrap())
                .unwrap();
        let error = fs_request.write_to_bytes(&mut buf);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let ByteConversionError::ToSliceTooSmall { found, expected } = error {
            assert_eq!(found, 2);
            assert_eq!(expected, 13);
        } else {
            panic!("unexpected error {:?}", error);
        }
    }

    #[test]
    fn test_read_from_buf_too_small() {
        let buf: [u8; 1] = [0; 1];
        let error = FilestoreRequestTlv::from_bytes(&buf);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let TlvLvError::ByteConversion(ByteConversionError::FromSliceTooSmall {
            found,
            expected,
        }) = error
        {
            assert_eq!(found, 1);
            assert_eq!(expected, 2);
        } else {
            panic!("unexpected error {:?}", error);
        }
    }

    #[test]
    fn test_buf_too_large() {
        let buf_too_large: [u8; u8::MAX as usize + 1] = [0; u8::MAX as usize + 1];
        let tlv_res = Tlv::new(TlvType::MsgToUser, &buf_too_large);
        assert!(tlv_res.is_err());
        let error = tlv_res.unwrap_err();
        if let TlvLvError::DataTooLarge(size) = error {
            assert_eq!(size, u8::MAX as usize + 1);
            assert_eq!(
                error.to_string(),
                "data with size 256 larger than allowed 255 bytes"
            );
        } else {
            panic!("unexpected error {:?}", error);
        }
    }

    #[test]
    fn test_deserialization_custom_tlv_type() {
        let mut buf: [u8; 4] = [0; 4];
        buf[0] = 3;
        buf[1] = 1;
        buf[2] = 5;
        let tlv = Tlv::from_bytes(&buf);
        assert!(tlv.is_ok());
        let tlv = tlv.unwrap();
        assert_eq!(tlv.tlv_type_field(), TlvTypeField::Custom(3));
        assert!(!tlv.is_standard_tlv());
        assert_eq!(tlv.value().len(), 1);
        assert_eq!(tlv.len_full(), 3);
    }

    fn generic_fs_request_test_one_file(
        action_code: FilestoreActionCode,
    ) -> FilestoreRequestTlv<'static, 'static> {
        assert!(!fs_request_has_second_filename(action_code));
        let first_name = Lv::new_from_str(TLV_TEST_STR_0).unwrap();
        let fs_request = match action_code {
            FilestoreActionCode::CreateFile => FilestoreRequestTlv::new_create_file(first_name),
            FilestoreActionCode::DeleteFile => FilestoreRequestTlv::new_delete_file(first_name),
            FilestoreActionCode::CreateDirectory => {
                FilestoreRequestTlv::new_create_directory(first_name)
            }
            FilestoreActionCode::RemoveDirectory => {
                FilestoreRequestTlv::new_remove_directory(first_name)
            }
            FilestoreActionCode::DenyFile => FilestoreRequestTlv::new_deny_file(first_name),
            FilestoreActionCode::DenyDirectory => {
                FilestoreRequestTlv::new_deny_directory(first_name)
            }
            _ => panic!("invalid action code"),
        };
        assert!(fs_request.is_ok());
        let fs_request = fs_request.unwrap();
        assert_eq!(fs_request.len_value(), 1 + first_name.len_full());
        assert_eq!(fs_request.len_full(), fs_request.len_value() + 2);
        assert_eq!(fs_request.action_code(), action_code);
        assert_eq!(fs_request.first_name(), first_name);
        assert_eq!(fs_request.second_name(), None);
        fs_request
    }

    fn generic_fs_request_test_two_files(
        action_code: FilestoreActionCode,
    ) -> FilestoreRequestTlv<'static, 'static> {
        assert!(fs_request_has_second_filename(action_code));
        let first_name = Lv::new_from_str(TLV_TEST_STR_0).unwrap();
        let second_name = Lv::new_from_str(TLV_TEST_STR_1).unwrap();
        let fs_request = match action_code {
            FilestoreActionCode::ReplaceFile => {
                FilestoreRequestTlv::new_replace_file(first_name, second_name)
            }
            FilestoreActionCode::AppendFile => {
                FilestoreRequestTlv::new_append_file(first_name, second_name)
            }
            FilestoreActionCode::RenameFile => {
                FilestoreRequestTlv::new_rename_file(first_name, second_name)
            }
            _ => panic!("invalid action code"),
        };
        assert!(fs_request.is_ok());
        let fs_request = fs_request.unwrap();
        assert_eq!(
            fs_request.len_value(),
            1 + first_name.len_full() + second_name.len_full()
        );
        assert_eq!(
            fs_request.tlv_type_field(),
            TlvTypeField::Standard(TlvType::FilestoreRequest)
        );
        assert_eq!(fs_request.len_full(), fs_request.len_value() + 2);
        assert_eq!(fs_request.len_written(), fs_request.len_full());
        assert_eq!(fs_request.action_code(), action_code);
        assert_eq!(fs_request.first_name(), first_name);
        assert!(fs_request.second_name().is_some());
        assert_eq!(fs_request.second_name().unwrap(), second_name);
        fs_request
    }

    #[test]
    fn test_fs_request_basic_create_file() {
        generic_fs_request_test_one_file(FilestoreActionCode::CreateFile);
    }

    #[test]
    fn test_fs_request_basic_delete() {
        generic_fs_request_test_one_file(FilestoreActionCode::DeleteFile);
    }

    #[test]
    fn test_fs_request_basic_create_dir() {
        generic_fs_request_test_one_file(FilestoreActionCode::CreateDirectory);
    }

    #[test]
    fn test_fs_request_basic_remove_dir() {
        generic_fs_request_test_one_file(FilestoreActionCode::RemoveDirectory);
    }

    #[test]
    fn test_fs_request_basic_deny_file() {
        generic_fs_request_test_one_file(FilestoreActionCode::DenyFile);
    }

    #[test]
    fn test_fs_request_basic_deny_dir() {
        generic_fs_request_test_one_file(FilestoreActionCode::DenyDirectory);
    }

    #[test]
    fn test_fs_request_basic_append_file() {
        generic_fs_request_test_two_files(FilestoreActionCode::AppendFile);
    }

    #[test]
    fn test_fs_request_basic_rename_file() {
        generic_fs_request_test_two_files(FilestoreActionCode::RenameFile);
    }

    #[test]
    fn test_fs_request_basic_replace_file() {
        generic_fs_request_test_two_files(FilestoreActionCode::ReplaceFile);
    }

    fn check_fs_request_first_part(
        buf: &[u8],
        action_code: FilestoreActionCode,
        expected_val_len: u8,
    ) -> usize {
        assert_eq!(buf[0], TlvType::FilestoreRequest as u8);
        assert_eq!(buf[1], expected_val_len);
        assert_eq!((buf[2] >> 4) & 0b1111, action_code as u8);
        let lv = Lv::from_bytes(&buf[3..]);
        assert!(lv.is_ok());
        let lv = lv.unwrap();
        assert_eq!(lv.value_as_str().unwrap().unwrap(), TLV_TEST_STR_0);
        3 + lv.len_full()
    }

    #[test]
    fn test_fs_request_serialization_one_file() {
        let req = generic_fs_request_test_one_file(FilestoreActionCode::CreateFile);
        let mut buf: [u8; 64] = [0; 64];
        let res = req.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, 3 + 1 + TLV_TEST_STR_0.len());
        assert_eq!(written, req.len_full());
        check_fs_request_first_part(
            &buf,
            FilestoreActionCode::CreateFile,
            1 + 1 + TLV_TEST_STR_0.len() as u8,
        );
    }

    #[test]
    fn test_fs_request_deserialization_one_file() {
        let req = generic_fs_request_test_one_file(FilestoreActionCode::CreateFile);
        let mut buf: [u8; 64] = [0; 64];
        let res = req.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let req_conv_back = FilestoreRequestTlv::from_bytes(&buf);
        assert!(req_conv_back.is_ok());
        let req_conv_back = req_conv_back.unwrap();
        assert_eq!(req_conv_back, req);
    }

    #[test]
    fn test_fs_request_serialization_two_files() {
        let req = generic_fs_request_test_two_files(FilestoreActionCode::RenameFile);
        let mut buf: [u8; 64] = [0; 64];
        let res = req.write_to_bytes(&mut buf);
        assert!(res.is_ok());
        let written = res.unwrap();
        assert_eq!(written, req.len_full());
        assert_eq!(
            written,
            3 + 1 + TLV_TEST_STR_0.len() + 1 + TLV_TEST_STR_1.len()
        );
        let current_idx = check_fs_request_first_part(
            &buf,
            FilestoreActionCode::RenameFile,
            1 + 1 + TLV_TEST_STR_0.len() as u8 + 1 + TLV_TEST_STR_1.len() as u8,
        );
        let second_lv = Lv::from_bytes(&buf[current_idx..]);
        assert!(second_lv.is_ok());
        let second_lv = second_lv.unwrap();
        assert_eq!(second_lv.value_as_str().unwrap().unwrap(), TLV_TEST_STR_1);
        assert_eq!(current_idx + second_lv.len_full(), req.len_full());
    }

    #[test]
    fn test_fs_request_deserialization_two_files() {
        let req = generic_fs_request_test_two_files(FilestoreActionCode::RenameFile);
        let mut buf: [u8; 64] = [0; 64];
        req.write_to_bytes(&mut buf).unwrap();
        let req_conv_back = FilestoreRequestTlv::from_bytes(&buf);
        assert!(req_conv_back.is_ok());
        let req_conv_back = req_conv_back.unwrap();
        assert_eq!(req_conv_back, req);
    }

    #[test]
    fn test_fs_response_state_one_path() {
        let lv_0 = Lv::new_from_str(TLV_TEST_STR_0).unwrap();
        let response = FilestoreResponseTlv::new_no_filestore_message(
            FilestoreActionCode::CreateFile,
            0b0001,
            lv_0,
            None,
        )
        .expect("creating response failed");
        assert_eq!(response.status_code(), 0b0001);
        assert_eq!(response.action_code(), FilestoreActionCode::CreateFile);
        assert_eq!(response.first_name(), lv_0);
        assert!(response.second_name().is_none());
    }
    #[test]
    fn test_fs_response_state_two_paths() {
        let lv_0 = Lv::new_from_str(TLV_TEST_STR_0).unwrap();
        let lv_1 = Lv::new_from_str(TLV_TEST_STR_1).unwrap();
        let response = FilestoreResponseTlv::new_no_filestore_message(
            FilestoreActionCode::RenameFile,
            0b0001,
            lv_0,
            Some(lv_1),
        )
        .expect("creating response failed");
        assert_eq!(response.status_code(), 0b0001);
        assert_eq!(response.action_code(), FilestoreActionCode::RenameFile);
        assert_eq!(response.first_name(), lv_0);
        assert!(response.second_name().is_some());
        assert!(response.second_name().unwrap() == lv_1);
        assert_eq!(
            response.len_full(),
            2 + 1 + lv_0.len_full() + lv_1.len_full() + 1
        );
    }

    #[test]
    fn test_fs_response_serialization() {
        let lv_0 = Lv::new_from_str(TLV_TEST_STR_0).unwrap();
        let response = FilestoreResponseTlv::new_no_filestore_message(
            FilestoreActionCode::CreateFile,
            0b0001,
            lv_0,
            None,
        )
        .expect("creating response failed");
        let mut buf: [u8; 32] = [0; 32];
        let written_len = response.write_to_bytes(&mut buf).unwrap();
        assert_eq!(written_len, 2 + 1 + lv_0.len_full() + 1);
        assert_eq!(buf[0], TlvType::FilestoreResponse as u8);
        assert_eq!(buf[1], written_len as u8 - 2);
        assert_eq!(
            (buf[2] >> 4) & 0b1111,
            FilestoreActionCode::CreateFile as u8
        );
        assert_eq!(buf[2] & 0b1111, 0b0001);
        let lv_read_back = Lv::from_bytes(&buf[3..]).unwrap();
        assert_eq!(lv_0, lv_read_back);
        let current_idx = 3 + lv_0.len_full();
        let fs_msg_empty = Lv::from_bytes(&buf[current_idx..]).unwrap();
        assert!(fs_msg_empty.is_empty());
    }

    #[test]
    fn test_fs_response_deserialization() {
        let lv_0 = Lv::new_from_str(TLV_TEST_STR_0).unwrap();
        let response = FilestoreResponseTlv::new_no_filestore_message(
            FilestoreActionCode::CreateFile,
            0b0001,
            lv_0,
            None,
        )
        .expect("creating response failed");
        let mut buf: [u8; 32] = [0; 32];
        response.write_to_bytes(&mut buf).unwrap();
        let response_read_back = FilestoreResponseTlv::from_bytes(&buf).unwrap();
        assert_eq!(response_read_back, response);
    }

    #[test]
    fn test_entity_it_tlv_to_tlv() {
        let entity_id = UbfU16::new(0x0102);
        let entity_id_tlv = EntityIdTlv::new(entity_id.into());
        let mut binding = [0; 16];
        let tlv = entity_id_tlv.to_tlv(&mut binding).unwrap();
        assert_eq!(
            tlv.tlv_type_field(),
            TlvTypeField::Standard(TlvType::EntityId)
        );
        assert_eq!(tlv.len_full(), 4);
        assert_eq!(tlv.len_value(), 2);
        assert_eq!(tlv.value(), &[0x01, 0x02]);
    }

    #[test]
    fn test_invalid_tlv_conversion() {
        let msg_to_user_tlv = Tlv::new_empty(TlvType::MsgToUser);
        let error = EntityIdTlv::try_from(msg_to_user_tlv);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let TlvLvError::InvalidTlvTypeField { found, expected } = error {
            assert_eq!(found, TlvType::MsgToUser as u8);
            assert_eq!(expected, Some(TlvType::EntityId as u8));
            assert_eq!(
                error.to_string(),
                "invalid TLV type field, found 2, expected Some(6)"
            );
        } else {
            panic!("unexpected error");
        }
    }

    #[test]
    fn test_entity_id_invalid_value_len() {
        let entity_id = UbfU16::new(0x0102);
        let entity_id_tlv = EntityIdTlv::new(entity_id.into());
        let mut buf: [u8; 32] = [0; 32];
        entity_id_tlv.write_to_bytes(&mut buf).unwrap();
        buf[1] = 12;
        let error = EntityIdTlv::from_bytes(&buf);
        assert!(error.is_err());
        let error = error.unwrap_err();
        if let TlvLvError::InvalidValueLength(len) = error {
            assert_eq!(len, 12);
            assert_eq!(error.to_string(), "invalid value length 12");
        } else {
            panic!("unexpected error");
        }
    }

    #[test]
    fn test_custom_tlv() {
        let custom_tlv = Tlv::new_with_custom_type(20, &[]).unwrap();
        assert!(custom_tlv.tlv_type().is_none());
        if let TlvTypeField::Custom(val) = custom_tlv.tlv_type_field() {
            assert_eq!(val, 20);
        } else {
            panic!("unexpected type field");
        }
        let tlv_as_vec = custom_tlv.to_vec();
        assert_eq!(tlv_as_vec.len(), 2);
        assert_eq!(tlv_as_vec[0], 20);
        assert_eq!(tlv_as_vec[1], 0);
    }
}
