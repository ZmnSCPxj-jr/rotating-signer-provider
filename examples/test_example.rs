use std::sync::Arc;
use lightning::sign::{KeysManager, NodeSigner, Recipient};
use rotating_signer_provider::{RotatingSignerProvider, FilesystemChannelKeyIdMap, SignerProviderId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Your existing KeysManager
    let seed = [42u8; 32];
    let starting_time_secs = 1234567890;
    let starting_time_nanos = 0;
    let keys_manager = Arc::new(KeysManager::new(&seed, starting_time_secs, starting_time_nanos));

    // Create a new KeysManager with different keys
    let new_seed = [99u8; 32];
    let new_keys_manager = Arc::new(KeysManager::new(&new_seed, starting_time_secs, starting_time_nanos));
    let new_keys_manager_id = SignerProviderId::from(new_keys_manager.get_node_id(Recipient::Node).unwrap());

    // Set up persistence
    let persistence = FilesystemChannelKeyIdMap::new("test_keys.db")?;

    // Build the rotating provider
    let _provider = RotatingSignerProvider::begin()
        .with_legacy_provider(keys_manager.clone())
        .with_persistent_channel_keys_id_map(Box::new(persistence))
        .with_entropy_source(keys_manager.clone())
        .add_active_provider(new_keys_manager_id, new_keys_manager)
        .build()?;

    Ok(())
}
