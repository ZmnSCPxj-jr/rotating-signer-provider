#[cfg(test)]
mod tests {

    use crate::RotatingSignerProvider;
    use crate::detail::WrappedChannelSigner;
    use crate::persistence::PersistentChannelKeyIdMap;
    use crate::SignerProviderId;
    use bitcoin::ScriptBuf;
    use lightning::ln::msgs::DecodeError;
    use lightning::ln::script::ShutdownScript;
    use lightning::sign::{EntropySource, KeysManager, SignerProvider};
    use std::io;
    use std::sync::Arc;

    /// Mock SignerProvider that panics on all methods - only for builder testing
    struct MockSignerProvider;

    impl SignerProvider for MockSignerProvider {
        type EcdsaSigner = WrappedChannelSigner;

        fn generate_channel_keys_id(&self, _inbound: bool, _channel_value_satoshis: u64, _user_channel_id: u128) -> [u8; 32] {
            panic!()
        }

        fn derive_channel_signer(&self, _channel_value_satoshis: u64, _channel_keys_id: [u8; 32]) -> Self::EcdsaSigner {
            panic!()
        }

        fn read_chan_signer(&self, _reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
            panic!()
        }

        fn get_destination_script(&self, _channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
            panic!()
        }

        fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
            panic!()
        }
    }

    /// Mock EntropySource that panics on all methods - only for builder testing
    struct MockEntropySource;

    impl EntropySource for MockEntropySource {
        fn get_secure_random_bytes(&self) -> [u8; 32] {
            panic!()
        }
    }

    /// Mock PersistentChannelKeyIdMap that panics on all methods - only for builder testing
    struct MockChannelKeyIdMap;

    impl PersistentChannelKeyIdMap for MockChannelKeyIdMap {
        type Error = String;

        fn store_mapping(
            &self,
            _outer_channel_keys_id: [u8; 32],
            _signer_id: SignerProviderId,
            _inner_channel_keys_id: [u8; 32],
        ) -> Result<(), Self::Error> {
            panic!()
        }

        fn get_inner_mapping(
            &self,
            _outer_channel_keys_id: &[u8; 32],
        ) -> Result<Option<(SignerProviderId, [u8; 32])>, Self::Error> {
            panic!()
        }
    }

    #[test]
    fn test_builder_basic_usage() {
        // Test that the builder can be constructed with minimum required parameters
        let mock_signer_provider = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let _provider = RotatingSignerProvider::begin()
            .with_legacy_provider(mock_signer_provider)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .build()
            .expect("Builder should succeed with minimum required parameters");
    }

    #[test]
    fn test_builder_comprehensive() {
        // Test that all builder methods can be called together
        let mock_signer_provider1 = Arc::new(MockSignerProvider);
        let mock_signer_provider2 = Arc::new(MockSignerProvider);
        let mock_signer_provider3 = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let id1 = SignerProviderId::from_bytes([1u8; 32]);
        let id2 = SignerProviderId::from_bytes([2u8; 32]);

        let _provider = RotatingSignerProvider::begin()
            .with_legacy_provider(mock_signer_provider1)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .add_active_provider(id1, mock_signer_provider2)
            .add_inactive_provider(id2, mock_signer_provider3)
            .with_persistence_error_handler(|_e| {
                panic!("Test persistence error handler")
            })
            .with_missing_provider_handler(|_id, _outer, _inner| -> io::Result<Arc<MockSignerProvider>> {
                Ok(Arc::new(MockSignerProvider))
            })
            .with_per_provider_unilateral_close_addresses()
            .build()
            .expect("Builder should succeed with all methods called");
    }

    #[test]
    fn test_builder_comprehensive_with_build_or_panic() {
        // Test that all builder methods can be called together using build_or_panic
        let mock_signer_provider1 = Arc::new(MockSignerProvider);
        let mock_signer_provider2 = Arc::new(MockSignerProvider);
        let mock_signer_provider3 = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let id1 = SignerProviderId::from_bytes([1u8; 32]);
        let id2 = SignerProviderId::from_bytes([2u8; 32]);

        let _provider = RotatingSignerProvider::begin()
            .with_legacy_provider(mock_signer_provider1)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .add_active_provider(id1, mock_signer_provider2)
            .add_inactive_provider(id2, mock_signer_provider3)
            .with_persistence_error_handler(|_e| {
                panic!("Test persistence error handler")
            })
            .with_missing_provider_handler(|_id, _outer, _inner| -> io::Result<Arc<MockSignerProvider>> {
                Ok(Arc::new(MockSignerProvider))
            })
            .with_per_provider_unilateral_close_addresses()
            .build_or_panic();
    }

    #[test]
    fn test_builder_missing_legacy_provider() {
        // Test that build() fails when legacy provider is missing
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let result = RotatingSignerProvider::<String>::begin()
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .build();

        let Err(error) = result else { panic!("Expected error but got success") };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_builder_missing_persistence() {
        // Test that build() fails when persistent channel keys ID map is missing
        let mock_signer_provider = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);

        let result = RotatingSignerProvider::<String>::begin()
            .with_legacy_provider(mock_signer_provider)
            .with_entropy_source(mock_entropy_source)
            .build();

        let Err(error) = result else { panic!("Expected error but got success") };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_builder_missing_entropy_source() {
        // Test that build() fails when entropy source is missing
        let mock_signer_provider = Arc::new(MockSignerProvider);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let result = RotatingSignerProvider::<String>::begin()
            .with_legacy_provider(mock_signer_provider)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .build();

        let Err(error) = result else { panic!("Expected error but got success") };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_builder_duplicate_active_provider_id() {
        // Test that build() fails when same ID is used for multiple active providers
        let mock_signer_provider1 = Arc::new(MockSignerProvider);
        let mock_signer_provider2 = Arc::new(MockSignerProvider);
        let mock_signer_provider3 = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let duplicate_id = SignerProviderId::from_bytes([1u8; 32]);

        let result = RotatingSignerProvider::<String>::begin()
            .with_legacy_provider(mock_signer_provider1)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .add_active_provider(duplicate_id, mock_signer_provider2)
            .add_active_provider(duplicate_id, mock_signer_provider3)
            .build();

        let Err(error) = result else { panic!("Expected error but got success") };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_builder_duplicate_inactive_provider_id() {
        // Test that build() fails when same ID is used for multiple inactive providers
        let mock_signer_provider1 = Arc::new(MockSignerProvider);
        let mock_signer_provider2 = Arc::new(MockSignerProvider);
        let mock_signer_provider3 = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let duplicate_id = SignerProviderId::from_bytes([2u8; 32]);

        let result = RotatingSignerProvider::<String>::begin()
            .with_legacy_provider(mock_signer_provider1)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .add_inactive_provider(duplicate_id, mock_signer_provider2)
            .add_inactive_provider(duplicate_id, mock_signer_provider3)
            .build();

        let Err(error) = result else { panic!("Expected error but got success") };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_builder_mixed_duplicate_provider_id() {
        // Test that build() fails when same ID is used for both active and inactive providers
        let mock_signer_provider1 = Arc::new(MockSignerProvider);
        let mock_signer_provider2 = Arc::new(MockSignerProvider);
        let mock_signer_provider3 = Arc::new(MockSignerProvider);
        let mock_entropy_source = Arc::new(MockEntropySource);
        let mock_persistence = Box::new(MockChannelKeyIdMap);

        let duplicate_id = SignerProviderId::from_bytes([3u8; 32]);

        let result = RotatingSignerProvider::<String>::begin()
            .with_legacy_provider(mock_signer_provider1)
            .with_persistent_channel_keys_id_map(mock_persistence)
            .with_entropy_source(mock_entropy_source)
            .add_active_provider(duplicate_id, mock_signer_provider2)
            .add_inactive_provider(duplicate_id, mock_signer_provider3)
            .build();

        let Err(error) = result else { panic!("Expected error but got success") };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_missing_provider_handler_compiles_with_io_result() {
        // Test that the handler signature compiles with io::Result return type
        let _builder = RotatingSignerProvider::<String>::begin()
            .with_missing_provider_handler(|id, _outer, _inner| -> io::Result<Arc<KeysManager>> {
                // Log the recovery attempt - this can fail with I/O error
                std::fs::write("/tmp/recovery.log", format!("Recovery attempt for {:?}", id))?;

                // Return an error indicating recovery is impossible
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Cannot recover provider from backup"
                ))
            });

        // Test that aborting handler also compiles
        let _builder2 = RotatingSignerProvider::<String>::begin()
            .with_missing_provider_handler(|id, _outer, _inner| -> io::Result<Arc<KeysManager>> {
                eprintln!("Fatal error: Missing SignerProvider {:?}", id);
                std::process::abort(); // This has type `!` which coerces to io::Result<Arc<KeysManager>>
            });

        // This test just verifies compilation - we don't actually call build()
        // since we haven't set required components
    }

    #[test]
    fn test_persistence_error_handler_compiles() {
        // Test that the handler signature compiles with different approaches
        let _builder = RotatingSignerProvider::<String>::begin()
            .with_persistence_error_handler(|e| {
                // Log the error - this can fail but handler should still abort
                let _ = std::fs::write("/tmp/fatal.log", format!("Fatal persistence error: {}", e));
                std::process::abort();
            });

        // Test that panic handler also compiles
        let _builder2 = RotatingSignerProvider::<String>::begin()
            .with_persistence_error_handler(|e| {
                panic!("Fatal persistence error: {}", e);
            });

        // Test that exit handler also compiles
        let _builder3 = RotatingSignerProvider::<String>::begin()
            .with_persistence_error_handler(|_e| {
                std::process::exit(1);
            });

        // This test just verifies compilation - we don't actually call build()
        // since we haven't set required components
    }
}
