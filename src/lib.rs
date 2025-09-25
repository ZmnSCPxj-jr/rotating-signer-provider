//! RotatingSignerProvider allows you to add new SignerProvider
//! instances with different keys to your Lightning node while
//! keeping existing channels operating with their original keys,
//! enabling gradual key rotation over time.
//!
//! # Basic Usage
//!
//! ```ignore
//! use rotating_signer_provider::{RotatingSignerProvider, FilesystemChannelKeyIdMap, SignerProviderId};
//!
//! // Your existing KeysManager
//! let keys_manager = Arc::new(KeysManager::new(&seed, starting_time_secs, starting_time_nanos));
//!
//! // Create a new KeysManager with different keys
//! let new_keys_manager = Arc::new(KeysManager::new(&new_seed, starting_time_secs, starting_time_nanos));
//! let new_keys_manager_id = SignerProviderId::from(new_keys_manager.get_node_id(Recipient::Node).unwrap());
//!
//! // Set up persistence
//! let persistence = FilesystemChannelKeyIdMap::new("keys.db")?;
//!
//! // Build the rotating provider
//! let provider = RotatingSignerProvider::begin()
//!     .with_legacy_provider(keys_manager.clone())
//!     .with_persistent_channel_keys_id_map(Box::new(persistence))
//!     .with_entropy_source(keys_manager.clone())
//!     .add_active_provider(new_keys_manager_id, new_keys_manager)
//!     .build()?;
//! ```
//!
//! # How it works
//!
//! The legacy provider (provided by `with_legacy_provider`) is
//! your existing SignerProvider that you used before switching to
//! RotatingSignerProvider - it handles all the channels you
//! currently have open.
//!
//! When you add new active SignerProviders, RotatingSignerProvider
//! associates newly-opened channels with one of these providers
//! using a unique `SignerProviderId` (typically derived from the
//! provider's public key), and stores those mappings in persistent
//! storage (such as using the built-in `FilesystemChannelKeyIdMap`).
//! New channels will use keys from your new `add_active_provider`,
//! and not the legacy provider --- but all the channels from the
//! legacy provider will continue working seamlessly.
//!
//! All channels will use the SignerProvider they were opened with,
//! by looking up the correct provider in this persistent map. This
//! ensures that all channels can be properly signed even after
//! restarts, while new channels gradually adopt the new signing
//! keys as they are opened.
//!
//! Onchain funds from channel closure will remain with your legacy
//! provider.
//!
//! # Safety considerations
//!
//! - **Persistence requirements**: The channel keys ID map should
//!   be as persistent as your ChannelMonitor persistent storage,
//!   and as redundantly replicated.
//!
//! - **SignerProviderId stability**: Each additional, non-legacy
//!   provider must have a unique identifier that remains the same
//!   across restarts - we recommend using the provider's root
//!   public key or deriving it from that to ensure stability.
//!
//! - **Backup requirements**: Of course, you should back up the
//!   seed words of the keys for all SignerProviders you give.
//!
//! # Start Exploring
//!
//! - [`RotatingSignerProvider::begin()`]
//! - [`RotatingSignerProvider`]
//! - [`RotatingSignerProviderBuilder`]
//! - [`SignerProviderId`]
//! - [`PersistentChannelKeyIdMap`]

use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::ScriptBuf;
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction, ClosingTransaction,
};
use lightning::ln::msgs::{DecodeError, UnsignedChannelAnnouncement};
use lightning::ln::script::ShutdownScript;
use lightning_types::payment::PaymentPreimage;
use lightning::sign::{ChannelSigner, EntropySource, HTLCDescriptor, SignerProvider};
use lightning::sign::ecdsa::EcdsaChannelSigner;

use secp256k1::{PublicKey, SecretKey, Secp256k1};
use std::collections::HashMap;

mod builder;
mod detail;
pub mod persistence;

pub use builder::RotatingSignerProviderBuilder;
pub use persistence::{PersistentChannelKeyIdMap, FilesystemChannelKeyIdMap};

/// The concrete channel signer type returned by [`RotatingSignerProvider`].
///
/// `RotatingChannelSigner` is a standard implementation of [`EcdsaChannelSigner`]
/// as required by LDK. It wraps the actual signer implementation from your underlying
/// [`SignerProvider`] instances and handles the routing between different providers
/// transparently.
///
/// Users of [`RotatingSignerProvider`] will receive instances of this type when LDK
/// calls [`derive_channel_signer`](SignerProvider::derive_channel_signer), but typically
/// you won't need to interact with it directly - just pass it to LDK components like
/// [`ChannelManager`](lightning::ln::channelmanager::ChannelManager).
///
/// This type implements all the standard LDK signer traits:
/// - [`ChannelSigner`]
/// - [`EcdsaChannelSigner`]
pub struct RotatingChannelSigner {
    inner: detail::WrappedChannelSigner,
}

impl RotatingChannelSigner {
    pub(crate) fn new(inner: detail::WrappedChannelSigner) -> Self {
        Self { inner }
    }
}

impl ChannelSigner for RotatingChannelSigner {
    fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> Result<PublicKey, ()> {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
        self.inner.release_commitment_secret(idx)
    }

    fn validate_holder_commitment(
        &self,
        holder_tx: &HolderCommitmentTransaction,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        self.inner.validate_holder_commitment(holder_tx, outbound_htlc_preimages)
    }

    fn validate_counterparty_revocation(&self, idx: u64, secret: &SecretKey) -> Result<(), ()> {
        self.inner.validate_counterparty_revocation(idx, secret)
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.inner.channel_keys_id()
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.pubkeys()
    }

    fn provide_channel_parameters(&mut self, parameters: &ChannelTransactionParameters) {
        self.inner.provide_channel_parameters(parameters)
    }
}

impl EcdsaChannelSigner for RotatingChannelSigner {
    fn sign_counterparty_commitment(
        &self,
        commitment_tx: &CommitmentTransaction,
        inbound_htlc_preimages: Vec<PaymentPreimage>,
        outbound_htlc_preimages: Vec<PaymentPreimage>,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.inner.sign_counterparty_commitment(commitment_tx, inbound_htlc_preimages, outbound_htlc_preimages, secp_ctx)
    }

    fn sign_holder_commitment(
        &self,
        commitment_tx: &HolderCommitmentTransaction,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_holder_commitment(commitment_tx, secp_ctx)
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_output(justice_tx, input, amount, per_commitment_key, secp_ctx)
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_key: &SecretKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_justice_revoked_htlc(justice_tx, input, amount, per_commitment_key, htlc, secp_ctx)
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        htlc_descriptor: &HTLCDescriptor,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_holder_htlc_transaction(htlc_tx, input, htlc_descriptor, secp_ctx)
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        input: usize,
        amount: u64,
        per_commitment_point: &PublicKey,
        htlc: &HTLCOutputInCommitment,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_counterparty_htlc_transaction(htlc_tx, input, amount, per_commitment_point, htlc, secp_ctx)
    }

    fn sign_closing_transaction(
        &self,
        closing_tx: &ClosingTransaction,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_closing_transaction(closing_tx, secp_ctx)
    }

    fn sign_holder_anchor_input(
        &self,
        anchor_tx: &Transaction,
        input: usize,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_holder_anchor_input(anchor_tx, input, secp_ctx)
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        msg: &UnsignedChannelAnnouncement,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_channel_announcement_with_funding_key(msg, secp_ctx)
    }

    fn sign_splicing_funding_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        input_value: u64,
        secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.inner.sign_splicing_funding_input(tx, input_index, input_value, secp_ctx)
    }
}



/// A unique identifier for a SignerProvider instance.
///
/// This 32-byte identifier must be universally unique for each SignerProvider instance
/// that is added to a RotatingSignerProvider. It serves as the permanent identifier
/// for mapping channels to their respective SignerProviders.
///
/// It is important that the same SignerProviderId is given across restarts of the program
/// for a particular SignerProvider. This ensures that channels can be correctly mapped back
/// to their original SignerProvider after a restart.
///
/// There are several recommended ways to generate a SignerProviderId:
///
/// 1. From a SignerProvider's root public key (RECOMMENDED):
///    - If your SignerProvider has a concept of a root/master public key,
///    - You can use its X coordinate directly as the SignerProviderId
///    - This naturally provides the same ID across restarts as long as the key remains the same
///
/// 2. From a hash of a public key or other unique data:
///    - Hash any unique identifying data of your SignerProvider
///    - For example, hash the serialized form of a public key
///    - IMPORTANT: Must hash the same exact data across restarts
///
/// 3. Generate and store a random 32-byte value:
///    - Must ensure it's truly random to avoid collisions
///    - CRITICAL: Must persistently store and reload this value
///    - Must use the exact same stored value across all restarts
///    - This is useful when your SignerProvider doesn't have a natural unique identifier
///
/// The crucial requirements are:
/// 1. SAME value must be used across restarts for the same SignerProvider
/// 2. Different values must be used for different SignerProviders
/// 3. Values must remain stable even across lightning node restarts
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SignerProviderId([u8; 32]);

impl SignerProviderId {
    /// Creates a new SignerProviderId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SignerProviderId(bytes)
    }

    /// Returns the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<Sha256Hash> for SignerProviderId {
    fn from(hash: Sha256Hash) -> Self {
        SignerProviderId(hash.to_byte_array())
    }
}

impl From<PublicKey> for SignerProviderId {
    fn from(pubkey: PublicKey) -> Self {
        // Get the 33-byte compressed serialization
        let serialized = pubkey.serialize();
        // The X coordinate is the last 32 bytes (first byte is the parity)
        let mut x_coord = [0u8; 32];
        x_coord.copy_from_slice(&serialized[1..]);
        SignerProviderId(x_coord)
    }
}

/// A signer provider that accepts your 'legacy' existing SignerProvider, then allows adding new
/// SignerProviders with different keys and signing procedures, so you can, over time, rotate keys
/// as you reopen channels.
pub struct RotatingSignerProvider<PersistenceError: std::fmt::Display> {
    inner: std::sync::Mutex<Inner<PersistenceError>>,
}

struct Inner<PersistenceError: std::fmt::Display> {
    // Core providers
    legacy_provider: Box<dyn detail::ErasedSignerProvider>,
    providers: HashMap<SignerProviderId, Box<dyn detail::ErasedSignerProvider>>,

    // Active provider management
    active_provider_ids: Vec<SignerProviderId>,
    round_robin_counter: usize,

    // Infrastructure
    entropy_source: Box<dyn EntropySource>,
    channel_keys_id_map: Box<dyn PersistentChannelKeyIdMap<Error = PersistenceError>>,

    // Configuration
    per_provider_unilateral_close_addresses: bool,

    // Error handlers
    persistence_error_handler: Box<dyn Fn(&PersistenceError) -> () + Send + Sync>,
    missing_provider_handler: Box<dyn Fn(SignerProviderId, [u8; 32], [u8; 32]) -> Box<dyn detail::ErasedSignerProvider> + Send + Sync>,
}

impl<PersistenceError: std::fmt::Display> SignerProvider for RotatingSignerProvider<PersistenceError> {
    type EcdsaSigner = RotatingChannelSigner;

    fn generate_channel_keys_id(
        &self,
        inbound: bool,
        channel_value_satoshis: u64,
        user_channel_id: u128,
    ) -> [u8; 32] {
        let mut inner = self.inner.lock().unwrap();

        if !inner.active_provider_ids.is_empty() {
            // Select active provider using round-robin
            let provider_id = inner.active_provider_ids[inner.round_robin_counter];

            // Update counter
            inner.round_robin_counter = (inner.round_robin_counter + 1) % inner.active_provider_ids.len();

            // Get the selected provider
            let selected_provider = inner.providers.get(&provider_id).unwrap();

            // Generate outer channel_keys_id using entropy source
            let outer_channel_keys_id = inner.entropy_source.get_secure_random_bytes();

            // Get inner channel_keys_id from selected provider
            let inner_channel_keys_id = selected_provider.generate_channel_keys_id(
                inbound,
                channel_value_satoshis,
                user_channel_id,
            );

            // Store the mapping
            if let Err(e) = inner.channel_keys_id_map.store_mapping(
                outer_channel_keys_id,
                provider_id,
                inner_channel_keys_id,
            ) {
                (inner.persistence_error_handler)(&e);
            }

            outer_channel_keys_id
        } else {
            // Use legacy provider - direct passthrough
            inner.legacy_provider.generate_channel_keys_id(
                inbound,
                channel_value_satoshis,
                user_channel_id,
            )
        }
    }

    fn derive_channel_signer(
        &self,
        channel_value_satoshis: u64,
        channel_keys_id: [u8; 32],
    ) -> Self::EcdsaSigner {
        let outer_channel_keys_id = channel_keys_id;
        let mut inner = self.inner.lock().unwrap();

        // Check if this is a mapped channel (outer -> inner mapping exists)
        match inner.channel_keys_id_map.get_inner_mapping(&outer_channel_keys_id) {
            Ok(Some((signer_provider_id, inner_channel_keys_id))) => {
                // This is a mapped channel - route to the correct provider
                if let Some(provider) = inner.providers.get(&signer_provider_id) {
                    let wrapped_signer = provider.derive_channel_signer(channel_value_satoshis, inner_channel_keys_id);
                    // Set the outer channel_keys_id so it returns the right ID to LDK
                    wrapped_signer.set_outer_channel_keys_id(outer_channel_keys_id);
                    RotatingChannelSigner::new(wrapped_signer)
                } else {
                    // Provider is missing - call the missing provider handler
                    let replacement_provider = (inner.missing_provider_handler)(
                        signer_provider_id,
                        outer_channel_keys_id,
                        inner_channel_keys_id,
                    );
                    let wrapped_signer = replacement_provider.derive_channel_signer(channel_value_satoshis, inner_channel_keys_id);
                    wrapped_signer.set_outer_channel_keys_id(outer_channel_keys_id);

                    // Add the replacement provider to our providers map for future use
                    inner.providers.insert(signer_provider_id, replacement_provider);

                    RotatingChannelSigner::new(wrapped_signer)
                }
            }
            Ok(None) => {
                // No mapping found - this is a legacy channel
                let wrapped_signer = inner.legacy_provider.derive_channel_signer(channel_value_satoshis, outer_channel_keys_id);
                // Don't set outer ID - legacy keyspace IS the outer keyspace
                RotatingChannelSigner::new(wrapped_signer)
            }
            Err(e) => {
                // Persistence error - call the error handler (it will never return)
                (inner.persistence_error_handler)(&e);
                unreachable!()
            }
        }
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<Self::EcdsaSigner, DecodeError> {
        // Obviously, channels that were serialized pre-0.0.113 were written by the legacy
        // provider that was in use back then.
        let inner = self.inner.lock().unwrap();
        let wrapped_signer = inner.legacy_provider.read_chan_signer(reader)?;
        Ok(RotatingChannelSigner::new(wrapped_signer))
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        let mut inner = self.inner.lock().unwrap();

        if !inner.per_provider_unilateral_close_addresses {
            // Default behavior: always use legacy provider (drop-in replacement)
            return inner.legacy_provider.get_destination_script(channel_keys_id);
        }

        // Advanced behavior: route to specific provider based on channel mapping
        let outer_channel_keys_id = channel_keys_id;

        // Check if this is a mapped channel (outer -> inner mapping exists)
        match inner.channel_keys_id_map.get_inner_mapping(&outer_channel_keys_id) {
            Ok(Some((signer_provider_id, inner_channel_keys_id))) => {
                // This is a mapped channel - route to the correct provider
                if let Some(provider) = inner.providers.get(&signer_provider_id) {
                    provider.get_destination_script(inner_channel_keys_id)
                } else {
                    // Provider is missing - call the missing provider handler
                    let replacement_provider = (inner.missing_provider_handler)(
                        signer_provider_id,
                        outer_channel_keys_id,
                        inner_channel_keys_id,
                    );

                    // Add the replacement provider to our providers map for future use
                    inner.providers.insert(signer_provider_id, replacement_provider);

                    // Now get the provider from the map and call it
                    inner.providers.get(&signer_provider_id).unwrap().get_destination_script(inner_channel_keys_id)
                }
            }
            Ok(None) => {
                // No mapping found - this is a legacy channel
                inner.legacy_provider.get_destination_script(outer_channel_keys_id)
            }
            Err(e) => {
                // Persistence error - call the error handler (it will never return)
                (inner.persistence_error_handler)(&e);
                unreachable!()
            }
        }
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        let inner = self.inner.lock().unwrap();
        inner.legacy_provider.get_shutdown_scriptpubkey()
    }
}

impl<PersistenceError: std::fmt::Display> RotatingSignerProvider<PersistenceError> {
    /// Start building a new RotatingSignerProvider.
    ///
    /// This begins the builder pattern for constructing a RotatingSignerProvider. The builder
    /// requires at minimum:
    /// - A legacy provider (your existing SignerProvider)
    /// - A persistence implementation for storing channel key mappings
    /// - An entropy source for generating high-entropy channel keys IDs
    ///
    /// Optionally, you can:
    /// - Add active providers that will be used for new channels
    /// - Add inactive providers that can still sign but won't be used for new channels
    /// - Customize how persistence errors are handled
    /// - Customize how missing providers are handled
    ///
    /// Example:
    /// ```ignore
    /// # use std::io;
    /// # use rotating_signer_provider::RotatingSignerProvider;
    /// # use rotating_signer_provider::FilesystemChannelKeyIdMap;
    /// # fn example() -> io::Result<()> {
    /// let persistence = FilesystemChannelKeyIdMap::new("keys.db")?;
    /// let provider = RotatingSignerProvider::begin()
    ///     .with_legacy_provider(your_existing_signer)
    ///     .with_persistent_channel_keys_id_map(persistence)
    ///     .with_entropy_source(your_entropy_source)
    ///     .with_persistence_error_handler(|e| {
    ///         eprintln!("Fatal persistence error: {}", e);
    ///         std::process::exit(1);
    ///     })
    ///     .add_active_provider(new_id, new_signer)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn begin() -> RotatingSignerProviderBuilder<PersistenceError> {
        RotatingSignerProviderBuilder::new()
    }

    /// Internal constructor used by builder
    pub(crate) fn new(
        legacy_provider: Box<dyn detail::ErasedSignerProvider>,
        channel_keys_id_map: Box<dyn PersistentChannelKeyIdMap<Error = PersistenceError>>,
        entropy_source: Box<dyn EntropySource>,
        providers: HashMap<SignerProviderId, Box<dyn detail::ErasedSignerProvider>>,
        active_provider_ids: Vec<SignerProviderId>,
        persistence_error_handler: Box<dyn Fn(&PersistenceError) -> () + Send + Sync>,
        missing_provider_handler: Box<dyn Fn(SignerProviderId, [u8; 32], [u8; 32]) -> Box<dyn detail::ErasedSignerProvider> + Send + Sync>,
        per_provider_unilateral_close_addresses: bool,
    ) -> Self {
        let inner = Inner {
            legacy_provider,
            providers,
            active_provider_ids,
            round_robin_counter: 0,
            entropy_source,
            channel_keys_id_map,
            per_provider_unilateral_close_addresses,
            persistence_error_handler,
            missing_provider_handler,
        };

        Self {
            inner: std::sync::Mutex::new(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::sha256;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_signer_provider_id_from_sha256() {
        let hash = sha256::Hash::hash(&[1, 2, 3, 4]);
        let id = SignerProviderId::from(hash);
        assert_eq!(id.as_bytes(), hash.as_byte_array());
    }

    #[test]
    fn test_signer_provider_id_from_pubkey() {
        let secp = Secp256k1::new();
        // Create a dummy private key (1)
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let id = SignerProviderId::from(public_key);
        // The X coordinate should match what we get from the pubkey
        assert_eq!(id.as_bytes(), &public_key.serialize()[1..]);
    }
}
