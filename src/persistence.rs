use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tempfile::NamedTempFile;
use crate::SignerProviderId;

/// Maps between the channel_keys_id visible to LDK ("outer") and the internal
/// mapping to a specific SignerProvider and its own channel_keys_id ("inner").
///
/// When a new channel is created:
/// 1. RotatingSignerProvider selects an active SignerProvider
/// 2. Gets a channel_keys_id from that SignerProvider (inner_channel_keys_id)
/// 3. Generates its own channel_keys_id to return to LDK (outer_channel_keys_id)
/// 4. Stores the mapping between these values
///
/// This mapping is permanent and cannot be removed, as the LDK SignerProvider
/// interface does not provide any mechanism to notify about channel deletion or
/// key retirement.
pub trait PersistentChannelKeyIdMap {
    /// Error type returned by operations that might fail
    type Error;

    /// Store a mapping between:
    /// * outer_channel_keys_id: The channel_keys_id that RotatingSignerProvider returns to LDK
    /// * signer_id: The SignerProvider that was chosen for this channel
    /// * inner_channel_keys_id: The channel_keys_id that was returned by the chosen SignerProvider
    ///
    /// This mapping is permanent and cannot be removed.
    fn store_mapping(
        &self,
        outer_channel_keys_id: [u8; 32],
        signer_id: SignerProviderId,
        inner_channel_keys_id: [u8; 32],
    ) -> Result<(), Self::Error>;

    /// Retrieve the SignerProvider and its channel_keys_id associated with an outer channel_keys_id
    fn get_inner_mapping(
        &self,
        outer_channel_keys_id: &[u8; 32],
    ) -> Result<Option<(SignerProviderId, [u8; 32])>, Self::Error>;
}

/// A filesystem-based implementation of channel key ID mapping.
///
/// This implementation stores mappings in a single file, which is atomically
/// updated on each new mapping insertion using standard POSIX atomic file
/// replacement (write to temp file, fsync, rename, fsync dir).
///
/// Note that each new mapping requires rewriting the entire map file.
/// This is acceptable because channel opens (and thus new mappings)
/// are expected to be rare operations.
pub struct FilesystemChannelKeyIdMap {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    map: HashMap<[u8; 32], (SignerProviderId, [u8; 32])>,
    path: PathBuf,
}

impl FilesystemChannelKeyIdMap {
    /// Creates a new FilesystemChannelKeyIdMap that stores its data at the given path.
    ///
    /// The path should be to the file that will contain the mappings, not a directory.
    /// If the file exists, it will be loaded. If it doesn't exist, an empty map will
    /// be created and the file will be created when the first mapping is added.
    ///
    /// This constructor performs several filesystem tests to ensure we have the necessary
    /// permissions and space:
    /// 1. Permission to read/write the target file
    /// 2. Permission to create temporary files in the same directory
    /// 3. Permission to fsync files and directory
    /// 4. Available space for at least one full copy of the map (needed for atomic updates)
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();

        let map = if path.exists() {
            // Load existing mappings
            let mut file = File::open(&path)?;
            let mut map = HashMap::new();
            let mut record = [0u8; 96];

            while file.read_exact(&mut record).is_ok() {
                let mut outer_channel_keys_id = [0u8; 32];
                let mut signer_provider_bytes = [0u8; 32];
                let mut inner_channel_keys_id = [0u8; 32];

                outer_channel_keys_id.copy_from_slice(&record[0..32]);
                signer_provider_bytes.copy_from_slice(&record[32..64]);
                inner_channel_keys_id.copy_from_slice(&record[64..96]);

                map.insert(
                    outer_channel_keys_id,
                    (SignerProviderId::from_bytes(signer_provider_bytes), inner_channel_keys_id),
                );
            }
            map
        } else {
            HashMap::new()
        };

        // Test permissions and space by doing a full write
        Self::atomic_write_map(&path, &map)?;

        Ok(FilesystemChannelKeyIdMap {
            inner: Arc::new(Mutex::new(Inner { map, path })),
        })
    }

    /// Write the map to disk using POSIX atomic file update pattern:
    /// 1. Write to temporary file
    /// 2. fsync temporary file
    /// 3. Rename to target file
    /// 4. fsync parent directory
    fn atomic_write_map(
        path: &Path,
        map: &HashMap<[u8; 32], (SignerProviderId, [u8; 32])>,
    ) -> io::Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut temp = NamedTempFile::new_in(dir)?;

        // Write all mappings
        for (outer_id, (signer_id, inner_id)) in map {
            temp.write_all(outer_id)?;
            temp.write_all(signer_id.as_bytes())?;
            temp.write_all(inner_id)?;
        }

        // Ensure data is on disk
        temp.as_file().sync_all()?;

        // Atomically replace the old file
        temp.persist(path)?;

        // Ensure directory entry is updated
        let dir = File::open(dir)?;
        dir.sync_all()?;

        Ok(())
    }
}

impl PersistentChannelKeyIdMap for FilesystemChannelKeyIdMap {
    type Error = io::Error;

    fn store_mapping(
        &self,
        outer_channel_keys_id: [u8; 32],
        signer_id: SignerProviderId,
        inner_channel_keys_id: [u8; 32],
    ) -> Result<(), Self::Error> {
        let mut inner = self.inner.lock().unwrap();

        // Update in-memory map
        inner.map.insert(outer_channel_keys_id, (signer_id, inner_channel_keys_id));

        // Write to disk atomically
        Self::atomic_write_map(&inner.path, &inner.map)?;

        Ok(())
    }

    fn get_inner_mapping(
        &self,
        outer_channel_keys_id: &[u8; 32],
    ) -> Result<Option<(SignerProviderId, [u8; 32])>, Self::Error> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.map.get(outer_channel_keys_id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_map() -> io::Result<()> {
        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_owned();

        let map = FilesystemChannelKeyIdMap::new(&path)?;

        let outer_id = [1u8; 32];
        let signer_id = SignerProviderId::from_bytes([2u8; 32]);
        let inner_id = [3u8; 32];

        // Store a mapping
        map.store_mapping(outer_id, signer_id, inner_id)?;

        // Retrieve it
        let retrieved = map.get_inner_mapping(&outer_id)?;
        assert_eq!(retrieved, Some((signer_id, inner_id)));

        // Create new map instance to test persistence
        let map2 = FilesystemChannelKeyIdMap::new(&path)?;
        let retrieved2 = map2.get_inner_mapping(&outer_id)?;
        assert_eq!(retrieved2, Some((signer_id, inner_id)));

        Ok(())
    }
}
