use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::ScriptBuf;
use lightning::ln::chan_utils::{
    ChannelPublicKeys, ChannelTransactionParameters, CommitmentTransaction,
    HTLCOutputInCommitment, HolderCommitmentTransaction, ClosingTransaction,
};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::ln::script::ShutdownScript;
use lightning::ln::PaymentPreimage;
use lightning::ln::msgs::DecodeError;
use lightning::sign::{ChannelSigner, EntropySource, HTLCDescriptor, SignerProvider};
use lightning::sign::ecdsa::{EcdsaChannelSigner, WriteableEcdsaChannelSigner};
use lightning::util::ser::{Writeable, Writer};
use secp256k1::{PublicKey, SecretKey, Secp256k1};

use std::sync::Mutex;

/// Wraps a ChannelSigner to optionally return a different channel_keys_id while
/// delegating all actual signing operations to the inner signer.
///
/// If no outer channel_keys_id is set (None), returns the inner signer's channel_keys_id.
/// If an outer channel_keys_id is set (Some), returns that instead.
pub(crate) struct WrappedChannelSigner {
    inner: Box<dyn EcdsaChannelSigner>,
    outer_channel_keys_id: Mutex<Option<[u8; 32]>>,
}

impl WrappedChannelSigner {
    pub(crate) fn new(inner: Box<dyn EcdsaChannelSigner>) -> Self {
        Self {
            inner,
            outer_channel_keys_id: Mutex::new(None),
        }
    }

    pub(crate) fn set_outer_channel_keys_id(&self, id: [u8; 32]) {
        *self.outer_channel_keys_id.lock().unwrap() = Some(id);
    }
}

impl ChannelSigner for WrappedChannelSigner {
    fn get_per_commitment_point(&self, idx: u64, secp_ctx: &Secp256k1<secp256k1::All>) -> PublicKey {
        self.inner.get_per_commitment_point(idx, secp_ctx)
    }

    fn release_commitment_secret(&self, idx: u64) -> [u8; 32] {
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
        // If we have an outer ID set, use that, otherwise delegate to inner
        if let Some(id) = *self.outer_channel_keys_id.lock().unwrap() {
            id
        } else {
            self.inner.channel_keys_id()
        }
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        self.inner.pubkeys()
    }

    fn provide_channel_parameters(&mut self, parameters: &ChannelTransactionParameters) {
        self.inner.provide_channel_parameters(parameters)
    }
}

impl EcdsaChannelSigner for WrappedChannelSigner {
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
}

impl Writeable for WrappedChannelSigner {
    fn write<W: Writer>(&self, _: &mut W) -> Result<(), std::io::Error> {
        panic!("WrappedChannelSigner::write should never be called in LDK 0.0.121");
    }
}

impl WriteableEcdsaChannelSigner for WrappedChannelSigner {}

/// Type-erased SignerProvider trait that allows storing different SignerProvider
/// implementations in the same collection.
///
/// This trait mirrors the SignerProvider interface but returns WrappedChannelSigner
/// directly instead of the associated type, enabling object safety.
pub(crate) trait ErasedSignerProvider: Send + Sync {
    fn generate_channel_keys_id(&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32];

    fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> WrappedChannelSigner;

    fn read_chan_signer(&self, reader: &[u8]) -> Result<WrappedChannelSigner, DecodeError>;

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()>;

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()>;
}

/// Concrete wrapper that implements ErasedSignerProvider for any SignerProvider.
///
/// This struct wraps a concrete SignerProvider implementation and provides the
/// type erasure needed to store different provider types in the same collection.
pub(crate) struct WrappedSignerProvider<SP> {
    inner: SP,
}

impl<SP> WrappedSignerProvider<SP> {
    pub(crate) fn new(inner: SP) -> Self {
        Self { inner }
    }
}

impl<SP: std::ops::Deref + Send + Sync> ErasedSignerProvider for WrappedSignerProvider<SP>
where
    SP::Target: SignerProvider,
    <SP::Target as SignerProvider>::EcdsaSigner: 'static,
{
    fn generate_channel_keys_id(&self, inbound: bool, channel_value_satoshis: u64, user_channel_id: u128) -> [u8; 32] {
        self.inner.generate_channel_keys_id(inbound, channel_value_satoshis, user_channel_id)
    }

    fn derive_channel_signer(&self, channel_value_satoshis: u64, channel_keys_id: [u8; 32]) -> WrappedChannelSigner {
        let concrete_signer = self.inner.derive_channel_signer(channel_value_satoshis, channel_keys_id);
        WrappedChannelSigner::new(Box::new(concrete_signer))
    }

    fn read_chan_signer(&self, reader: &[u8]) -> Result<WrappedChannelSigner, DecodeError> {
        let concrete_signer = self.inner.read_chan_signer(reader)?;
        Ok(WrappedChannelSigner::new(Box::new(concrete_signer)))
    }

    fn get_destination_script(&self, channel_keys_id: [u8; 32]) -> Result<ScriptBuf, ()> {
        self.inner.get_destination_script(channel_keys_id)
    }

    fn get_shutdown_scriptpubkey(&self) -> Result<ShutdownScript, ()> {
        self.inner.get_shutdown_scriptpubkey()
    }
}

/// Concrete wrapper that implements EntropySource for any type that derefs to EntropySource.
///
/// This struct wraps a concrete EntropySource implementation and provides the
/// type erasure needed to store it as Box<dyn EntropySource>.
pub(crate) struct WrappedEntropySource<ES> {
    inner: ES,
}

impl<ES> WrappedEntropySource<ES> {
    pub(crate) fn new(inner: ES) -> Self {
        Self { inner }
    }
}

impl<ES: std::ops::Deref + Send + Sync> EntropySource for WrappedEntropySource<ES>
where
    ES::Target: EntropySource,
{
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        self.inner.get_secure_random_bytes()
    }
}

/// Concrete wrapper that implements PersistentChannelKeyIdMap for any type that derefs to PersistentChannelKeyIdMap.
///
/// This struct wraps a concrete PersistentChannelKeyIdMap implementation and provides the
/// type erasure needed to store it as Box<dyn PersistentChannelKeyIdMap>.
pub(crate) struct WrappedChannelKeyIdMap<M> {
    inner: M,
}

impl<M> WrappedChannelKeyIdMap<M> {
    pub(crate) fn new(inner: M) -> Self {
        Self { inner }
    }
}

impl<M: std::ops::Deref + Send + Sync> crate::persistence::PersistentChannelKeyIdMap for WrappedChannelKeyIdMap<M>
where
    M::Target: crate::persistence::PersistentChannelKeyIdMap,
{
    type Error = <M::Target as crate::persistence::PersistentChannelKeyIdMap>::Error;

    fn store_mapping(
        &self,
        outer_channel_keys_id: [u8; 32],
        signer_id: crate::SignerProviderId,
        inner_channel_keys_id: [u8; 32],
    ) -> Result<(), Self::Error> {
        self.inner.store_mapping(outer_channel_keys_id, signer_id, inner_channel_keys_id)
    }

    fn get_inner_mapping(
        &self,
        outer_channel_keys_id: &[u8; 32],
    ) -> Result<Option<(crate::SignerProviderId, [u8; 32])>, Self::Error> {
        self.inner.get_inner_mapping(outer_channel_keys_id)
    }
}

#[cfg(test)]
mod tests;
