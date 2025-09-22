use crate::detail::{ErasedSignerProvider, WrappedSignerProvider, WrappedEntropySource, WrappedChannelKeyIdMap};
use crate::persistence::PersistentChannelKeyIdMap;
use crate::SignerProviderId;
use lightning::sign::{EntropySource, SignerProvider};
use std::collections::HashMap;
use std::io;

#[cfg(test)]
mod tests;

/// Builder for RotatingSignerProvider.
pub struct RotatingSignerProviderBuilder<PersistenceError: std::fmt::Display + 'static> {
    legacy_provider: Option<Box<dyn ErasedSignerProvider>>,
    channel_keys_id_map: Option<Box<dyn PersistentChannelKeyIdMap<Error = PersistenceError>>>,
    entropy_source: Option<Box<dyn EntropySource>>,
    providers: HashMap<SignerProviderId, Box<dyn ErasedSignerProvider>>,
    active_provider_ids: Vec<SignerProviderId>,
    persistence_error_handler: Option<Box<dyn Fn(&PersistenceError) -> () + Send + Sync>>,
    missing_provider_handler: Option<Box<dyn Fn(SignerProviderId, [u8; 32], [u8; 32]) -> Box<dyn ErasedSignerProvider> + Send + Sync>>,
    per_provider_unilateral_close_addresses: bool,
    error: Option<io::Error>,
}

impl<PersistenceError: std::fmt::Display + 'static> RotatingSignerProviderBuilder<PersistenceError> {
    /// Creates a new empty builder
    pub(crate) fn new() -> Self {
        Self {
            legacy_provider: None,
            channel_keys_id_map: None,
            entropy_source: None,
            providers: HashMap::new(),
            active_provider_ids: Vec::new(),
            persistence_error_handler: None,
            missing_provider_handler: None,
            per_provider_unilateral_close_addresses: false,
            error: None,
        }
    }

    /// Set the legacy provider - your existing `SignerProvider` from before switching
    /// to `RotatingSignerProvider`.
    ///
    /// This provider continues to sign for its existing channels. For new channels,
    /// it is only used as a fallback if there are no active providers set (see
    /// [`Self::add_active_provider`]).
    ///
    /// This should be the `SignerProvider` that was handling your existing channels
    /// before switching to `RotatingSignerProvider`. Typically this would be an
    /// `Arc<KeysManager>`, which you can conveniently pass to both this method and
    /// [`Self::with_entropy_source`].
    ///
    /// Required: This method must be called before [`Self::build`].
    pub fn with_legacy_provider<P>(mut self, provider: P) -> Self
    where
        P: std::ops::Deref + Send + Sync + 'static,
        P::Target: SignerProvider,
        <P::Target as SignerProvider>::EcdsaSigner: 'static,
    {
        self.legacy_provider = Some(Box::new(WrappedSignerProvider::new(provider)));
        self
    }

    /// Set the persistent channel keys ID map implementation.
    ///
    /// This maps channels to their respective SignerProviders. The mapping must
    /// persist across restarts to ensure channels remain associated with their
    /// original signers.
    ///
    /// See [`crate::FilesystemChannelKeyIdMap`] for a ready-to-use implementation.
    ///
    /// Required: This method must be called before [`Self::build`].
    pub fn with_persistent_channel_keys_id_map<M>(mut self, map: M) -> Self
    where
        M: std::ops::Deref + Send + Sync + 'static,
        M::Target: PersistentChannelKeyIdMap<Error = PersistenceError>,
    {
        self.channel_keys_id_map = Some(Box::new(WrappedChannelKeyIdMap::new(map)));
        self
    }

    /// Set the entropy source for generating high-entropy outer channel keys IDs.
    ///
    /// This is used to generate the outer `channel_keys_id` values that `RotatingSignerProvider`
    /// returns to LDK. High entropy is required to avoid collisions with the legacy
    /// `SignerProvider`'s `channel_keys_id` space.
    ///
    /// You should pass the same `EntropySource` that you will use for your `ChannelsManager`.
    /// Typically this would be an `Arc<KeysManager>`, which you can conveniently pass to both
    /// this method and [`Self::with_legacy_provider`].
    ///
    /// Required: This method must be called before [`Self::build`].
    pub fn with_entropy_source<E>(mut self, entropy_source: E) -> Self
    where
        E: std::ops::Deref + Send + Sync + 'static,
        E::Target: EntropySource,
    {
        self.entropy_source = Some(Box::new(WrappedEntropySource::new(entropy_source)));
        self
    }

    /// Add an active provider that will be used for new channels.
    ///
    /// Active providers are used when opening new channels. You can have multiple
    /// active providers - the RotatingSignerProvider will choose one when opening
    /// a new channel.
    ///
    /// See [`Self::add_inactive_provider`] when you want to retire a provider.
    ///
    /// Optional: You can add zero or more active providers. If none are added,
    /// the legacy provider will be used for new channels.
    pub fn add_active_provider<P>(mut self, id: SignerProviderId, provider: P) -> Self
    where
        P: std::ops::Deref + Send + Sync + 'static,
        P::Target: SignerProvider,
        <P::Target as SignerProvider>::EcdsaSigner: 'static,
    {
        if self.providers.contains_key(&id) {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("RotatingSignerProvider: id {:?} must be given only once, not multiple times", id)
            ));
            return self;
        }

        self.providers.insert(id, Box::new(WrappedSignerProvider::new(provider)));
        self.active_provider_ids.push(id);
        self
    }

    /// Add an inactive provider that can sign but won't be used for new channels.
    ///
    /// Inactive providers can still sign for their existing channels but will not
    /// be used for new channels. Use this when you want to retire a key - add it
    /// as inactive, wait for its channels to close naturally, then remove it.
    ///
    /// See [`Self::add_active_provider`] for providers that should handle new channels.
    ///
    /// Optional: You can add zero or more inactive providers.
    pub fn add_inactive_provider<P>(mut self, id: SignerProviderId, provider: P) -> Self
    where
        P: std::ops::Deref + Send + Sync + 'static,
        P::Target: SignerProvider,
        <P::Target as SignerProvider>::EcdsaSigner: 'static,
    {
        if self.providers.contains_key(&id) {
            self.error = Some(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("RotatingSignerProvider: id {:?} must be given only once, not multiple times", id)
            ));
            return self;
        }

        self.providers.insert(id, Box::new(WrappedSignerProvider::new(provider)));
        self
    }

    /// Set a custom persistence error handler.
    ///
    /// Called when channel-to-signer mappings cannot be persisted or loaded.
    /// This is a critical error as using the wrong signer could lead to fund loss.
    ///
    /// IMPORTANT: This handler MUST NOT RETURN. It must either:
    /// - Panic
    /// - Abort the process
    /// - Enter an infinite loop
    /// - Exit the process
    /// - Or otherwise ensure execution never continues
    ///
    /// Optional: If not set, defaults to printing to stderr and aborting.
    pub fn with_persistence_error_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&PersistenceError) -> () + Send + Sync + 'static,
    {
        self.persistence_error_handler = Some(Box::new(handler));
        self
    }

    /// Set a custom missing provider handler.
    ///
    /// Called when a channel requests a signer that cannot be found. This could
    /// happen if configuration is lost/corrupted or if a signer was removed too early.
    ///
    /// The handler must either:
    /// - Return `Ok(provider)` with a valid replacement SignerProvider that can handle the channel
    /// - Return `Err(io_error)` if recovery is impossible (system will abort for safety)
    /// - Never return (panic/abort) if recovery is impossible
    ///
    /// This allows implementing recovery strategies (e.g., restore from backup, logging)
    /// while ensuring we fail safely if recovery is impossible.
    ///
    /// # Examples
    ///
    /// Immediate abort when recovery is impossible:
    /// ```no_run
    /// use lightning::sign::KeysManager;
    /// use std::io;
    /// use std::sync::Arc;
    ///
    /// # use rotating_signer_provider::RotatingSignerProvider;
    /// let builder = RotatingSignerProvider::<String>::begin()
    ///     .with_missing_provider_handler(|id, _outer, _inner| -> io::Result<Arc<KeysManager>> {
    ///         // Log the fatal error - I/O operation can fail
    ///         std::fs::write("/var/log/lightning-fatal.log",
    ///             format!("FATAL: Missing SignerProvider {:?} - aborting for safety", id))?;
    ///         std::process::abort(); // Never returns
    ///     });
    /// ```
    ///
    /// Optional: If not set, defaults to printing details and aborting.
    pub fn with_missing_provider_handler<F, P>(mut self, handler: F) -> Self
    where
        F: Fn(SignerProviderId, [u8; 32], [u8; 32]) -> io::Result<P> + Send + Sync + 'static,
        P: std::ops::Deref + Send + Sync + 'static,
        P::Target: SignerProvider,
        <P::Target as SignerProvider>::EcdsaSigner: 'static,
    {
        // Wrap the user's handler to convert their SignerProvider to our internal type
        let wrapped_handler = move |id: SignerProviderId, outer: [u8; 32], inner: [u8; 32]| -> Box<dyn ErasedSignerProvider> {
            match handler(id, outer, inner) {
                Ok(provider) => Box::new(WrappedSignerProvider::new(provider)),
                Err(e) => {
                    eprintln!("Missing provider handler failed: {}", e);
                    eprintln!("  SignerProviderId: {:?}", id);
                    eprintln!("  Outer channel_keys_id: {:?}", outer);
                    eprintln!("  Inner channel_keys_id: {:?}", inner);
                    std::process::abort();
                }
            }
        };
        self.missing_provider_handler = Some(Box::new(wrapped_handler));
        self
    }

    /// NOT RECOMMENDED: Enable per-provider addresses for unilateral close scenarios.
    ///
    /// ⚠️ **WARNING: This option fragments your funds across multiple wallets and is NOT recommended for most users.**
    ///
    /// When enabled, **in LDK's implementation**, unilateral close scenarios will send funds to addresses
    /// controlled by the specific SignerProvider that was used for each channel. This includes:
    /// - Force-close by either party (to_local outputs after CSV delay)
    /// - Justice/penalty transactions (when counterparty broadcasts revoked commitment)
    /// - HTLC timeout/success transaction claims
    /// - Any other on-chain outputs that LDK detects as belonging to your channels
    ///
    /// This means your funds will be scattered across different on-chain wallets, each controlled by
    /// different SignerProvider seeds.
    ///
    /// **Problems with enabling this option:**
    ///
    /// - **WALLET FRAGMENTATION**: Your funds will go to different addresses controlled by different SignerProviders
    /// - **RECOVERY COMPLEXITY**: You must maintain access to ALL SignerProvider seeds to recover funds
    /// - **PARTIAL ISOLATION ONLY**: Cooperative closes still go to your legacy provider's address
    /// - **SURPRISING BEHAVIOR**: Most node software expects onchain funds to be in one wallet, not scattered
    /// - **BACKUP COMPLEXITY**: You need to backup and restore multiple seeds, not just one
    /// - **INCONSISTENT DESTINATIONS**: Unilateral-close and cooperative-close funds go to different places
    ///
    /// **When you might want this despite the warnings:**
    /// - You specifically need privacy isolation between different SignerProviders
    /// - You understand and accept the wallet fragmentation
    /// - You have robust procedures for managing multiple seeds
    /// - You prioritize privacy over convenience
    ///
    /// **Default behavior (if you DO NOT call this method):** All channel funds go to your legacy provider's
    /// addresses, regardless of which SignerProvider was used for signing. This provides consistent,
    /// predictable fund destinations that match your existing wallet setup.
    pub fn with_per_provider_unilateral_close_addresses(mut self) -> Self {
        self.per_provider_unilateral_close_addresses = true;
        self
    }

    /// Build the RotatingSignerProvider
    ///
    /// Returns an error if required components are missing. For a version that
    /// panics instead, see [`Self::build_or_panic`].
    ///
    /// Required components (these methods must be called before building):
    /// - [`Self::with_legacy_provider`]
    /// - [`Self::with_persistent_channel_keys_id_map`]
    /// - [`Self::with_entropy_source`]
    pub fn build(self) -> io::Result<crate::RotatingSignerProvider<PersistenceError>> {
        // Check for any accumulated errors first
        if let Some(error) = self.error {
            return Err(error);
        }

        let legacy_provider = self.legacy_provider.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "RotatingSignerProvider: legacy provider must be set"
            )
        })?;

        let channel_keys_id_map = self.channel_keys_id_map.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "RotatingSignerProvider: persistent channel keys ID map must be set"
            )
        })?;

        let entropy_source = self.entropy_source.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "RotatingSignerProvider: entropy source must be set"
            )
        })?;

        // Get or create the persistence error handler
        let persistence_error_handler: Box<dyn Fn(&PersistenceError) -> () + Send + Sync> = if let Some(handler) = self.persistence_error_handler {
            // Wrap the user's handler to ensure it never returns
            Box::new(move |e: &PersistenceError| {
                handler(e);
                // If we get here, the handler returned (which it shouldn't!)
                eprintln!("RotatingSignerProvider: persistence error handler returned unexpectedly");
                eprintln!("  Original persistence error: {}", e);
                eprintln!("  Handler was required to abort but returned instead");
                std::process::abort();
            })
        } else {
            Box::new(|e: &PersistenceError| {
                eprintln!("RotatingSignerProvider: Fatal persistence error: {}", e);
                std::process::abort();
            })
        };

        // Get or create the missing provider handler
        let missing_provider_handler = if let Some(handler) = self.missing_provider_handler {
            handler
        } else {
            Box::new(|id: SignerProviderId, outer: [u8; 32], inner: [u8; 32]| -> Box<dyn ErasedSignerProvider> {
                eprintln!("Fatal error: Missing SignerProvider");
                eprintln!("  SignerProviderId: {:?}", id);
                eprintln!("  Outer channel_keys_id: {:?}", outer);
                eprintln!("  Inner channel_keys_id: {:?}", inner);
                std::process::abort();
            })
        };

        Ok(crate::RotatingSignerProvider::new(
            legacy_provider,
            channel_keys_id_map,
            entropy_source,
            self.providers,
            self.active_provider_ids,
            persistence_error_handler,
            missing_provider_handler,
            self.per_provider_unilateral_close_addresses,
        ))
    }

    /// Build the RotatingSignerProvider, panicking if any required components are missing.
    ///
    /// This is a convenience wrapper around [`Self::build`] that panics with the error message
    /// if `build` returns `Err`. Use this when you know all required components are set
    /// and a panic is acceptable if they're not.
    ///
    /// # Panics
    ///
    /// Panics if required components are missing. See [`Self::build`] for the list of
    /// required components.
    pub fn build_or_panic(self) -> crate::RotatingSignerProvider<PersistenceError> {
        self.build().unwrap_or_else(|e| panic!("{}", e))
    }
}
