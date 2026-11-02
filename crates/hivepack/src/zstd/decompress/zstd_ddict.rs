//! Digested dictionaries: port of `decompress/zstd_ddict.c`.

use crate::zstd::common::error_private::{Result, error};
use crate::zstd::common::mem::read_le32;
use crate::zstd::common::zstd_internal::{ZSTD_FRAMEIDSIZE, ZSTD_MAGIC_DICTIONARY};
use crate::zstd::decompress::zstd_decompress::load_d_entropy;
use crate::zstd::decompress::zstd_decompress_internal::EntropyDTables;

/// `ZSTD_dictContentType_e`: how to read a dictionary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DictContentType {
    /// A zstd dictionary if it starts with the dictionary magic number,
    /// raw content otherwise (`ZSTD_dct_auto`).
    #[default]
    Auto,
    /// Raw content, whatever it starts with (`ZSTD_dct_rawContent`).
    RawContent,
    /// A zstd dictionary, or an error (`ZSTD_dct_fullDict`).
    FullDict,
}

/// `ZSTD_DDict`: a dictionary prepared for decompression, so that frames
/// using it start without the work of reading it.
///
/// The content is always copied in (`ZSTD_dlm_byCopy`).
pub struct DDict {
    /// The whole dictionary, header included: as in libzstd, matches may
    /// reach into all of it.
    pub(crate) content: Box<[u8]>,
    pub(crate) entropy: Box<EntropyDTables>,
    pub(crate) dict_id: u32,
    pub(crate) entropy_present: bool,
}

impl DDict {
    /// `ZSTD_createDDict`: reads `dict` as a zstd dictionary, or as raw
    /// content if it is not one.
    pub fn new(dict: &[u8]) -> Result<DDict> {
        DDict::with_content_type(dict, DictContentType::Auto)
    }

    /// `ZSTD_createDDict_advanced`, with the content copied in.
    pub fn with_content_type(dict: &[u8], content_type: DictContentType) -> Result<DDict> {
        // ZSTD_initDDict_internal
        let mut ddict = DDict {
            content: dict.into(),
            entropy: Box::default(),
            dict_id: 0,
            entropy_present: false,
        };
        ddict.load_entropy(content_type)?;
        Ok(ddict)
    }

    /// `ZSTD_loadEntropy_intoDDict`
    fn load_entropy(&mut self, content_type: DictContentType) -> Result<()> {
        self.dict_id = 0;
        self.entropy_present = false;
        if content_type == DictContentType::RawContent {
            return Ok(());
        }
        if self.content.len() < 8 {
            if content_type == DictContentType::FullDict {
                // Only actual dictionaries are accepted.
                return error!(DictionaryCorrupted);
            }
            // Raw content.
            return Ok(());
        }
        if read_le32(&self.content, 0) != ZSTD_MAGIC_DICTIONARY {
            if content_type == DictContentType::FullDict {
                return error!(DictionaryCorrupted);
            }
            return Ok(());
        }
        self.dict_id = read_le32(&self.content, ZSTD_FRAMEIDSIZE);
        if load_d_entropy(&mut self.entropy, &self.content).is_err() {
            return error!(DictionaryCorrupted);
        }
        self.entropy_present = true;
        Ok(())
    }

    /// `ZSTD_getDictID_fromDDict`: the dictionary's ID, 0 for raw content.
    pub fn dict_id(&self) -> u32 {
        self.dict_id
    }

    /// `ZSTD_DDict_dictSize`
    pub fn dict_size(&self) -> usize {
        self.content.len()
    }
}

impl std::fmt::Debug for DDict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DDict")
            .field("dict_id", &self.dict_id)
            .field("dict_size", &self.content.len())
            .field("entropy_present", &self.entropy_present)
            .finish()
    }
}
