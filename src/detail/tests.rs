use super::*;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::locktime::absolute::LockTime;
use bitcoin::{OutPoint, ScriptBuf};
use lightning::ln::chan_utils::{ChannelPublicKeys, ChannelTransactionParameters};
use lightning_types::payment::{PaymentHash, PaymentPreimage};
use lightning::ln::channel_keys::{RevocationBasepoint, DelayedPaymentBasepoint, HtlcBasepoint};
use lightning_types::features::{ChannelFeatures, ChannelTypeFeatures};
use lightning::ln::msgs::UnsignedChannelAnnouncement;
use lightning::routing::gossip::NodeId;
use lightning::sign::ChannelDerivationParameters;
use std::sync::atomic::{AtomicU64, Ordering};
use std::rc::Rc;

// Mock signer that just inverts bytes for signatures and counts calls
struct MockSigner {
    pubkeys: ChannelPublicKeys,
    inner_channel_keys_id: [u8; 32],
    sign_counter: Rc<AtomicU64>,
}

impl MockSigner {
    fn new() -> Self {
        Self::with_counter(Rc::new(AtomicU64::new(0)))
    }

    fn with_counter(counter: Rc<AtomicU64>) -> Self {
        // Create some dummy pubkeys
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[42; 32]).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret_key);

        Self {
            pubkeys: ChannelPublicKeys {
                funding_pubkey: pubkey,
                revocation_basepoint: RevocationBasepoint(pubkey),
                payment_point: pubkey,
                delayed_payment_basepoint: DelayedPaymentBasepoint(pubkey),
                htlc_basepoint: HtlcBasepoint(pubkey),
            },
            inner_channel_keys_id: [42u8; 32],
            sign_counter: counter,
        }
    }

    // Helper to create "signatures" by inverting bytes
    fn invert_bytes(input: &[u8]) -> [u8; 64] {
        let mut result = [0u8; 64];
        for (i, byte) in input.iter().take(64).enumerate() {
            result[i] = !byte;  // Invert each byte
        }
        result
    }
}

impl ChannelSigner for MockSigner {
    fn get_per_commitment_point(&self, _idx: u64, _secp_ctx: &Secp256k1<secp256k1::All>) -> Result<PublicKey, ()> {
        Ok(self.pubkeys.funding_pubkey)  // Just return funding pubkey
    }

    fn release_commitment_secret(&self, idx: u64) -> Result<[u8; 32], ()> {
        let mut secret = [0u8; 32];
        for i in 0..32 {
            secret[i] = idx as u8 + i as u8;  // Deterministic but obvious pattern
        }
        Ok(secret)
    }

    fn validate_holder_commitment(
        &self,
        _holder_tx: &HolderCommitmentTransaction,
        _preimages: Vec<PaymentPreimage>,
    ) -> Result<(), ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn validate_counterparty_revocation(&self, _idx: u64, _secret: &SecretKey) -> Result<(), ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn channel_keys_id(&self) -> [u8; 32] {
        self.inner_channel_keys_id
    }

    fn pubkeys(&self) -> &ChannelPublicKeys {
        &self.pubkeys
    }

    fn provide_channel_parameters(&mut self, _params: &ChannelTransactionParameters) {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
    }
}

impl EcdsaChannelSigner for MockSigner {
    fn sign_counterparty_commitment(
        &self,
        _commitment_tx: &CommitmentTransaction,
        _inbound_htlc_preimages: Vec<PaymentPreimage>,
        _outbound_htlc_preimages: Vec<PaymentPreimage>,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<(Signature, Vec<Signature>), ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        // Just invert some fixed bytes
        let sig_bytes = Self::invert_bytes(&[0x42; 64]);
        Ok((
            Signature::from_compact(&sig_bytes[..64]).unwrap(),
            vec![]
        ))
    }

    fn sign_holder_commitment(
        &self,
        _commitment_tx: &HolderCommitmentTransaction,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(&[0x42; 64]);
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_justice_revoked_output(
        &self,
        justice_tx: &Transaction,
        _input: usize,
        _amount: u64,
        _per_commitment_key: &SecretKey,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(justice_tx.txid().as_ref());
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_justice_revoked_htlc(
        &self,
        justice_tx: &Transaction,
        _input: usize,
        _amount: u64,
        _per_commitment_key: &SecretKey,
        _htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(justice_tx.txid().as_ref());
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_holder_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        _input: usize,
        _htlc_descriptor: &HTLCDescriptor,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(htlc_tx.txid().as_ref());
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_counterparty_htlc_transaction(
        &self,
        htlc_tx: &Transaction,
        _input: usize,
        _amount: u64,
        _per_commitment_point: &PublicKey,
        _htlc: &HTLCOutputInCommitment,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(htlc_tx.txid().as_ref());
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_closing_transaction(
        &self,
        _closing_tx: &ClosingTransaction,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(&[0x42; 64]);
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_holder_anchor_input(
        &self,
        anchor_tx: &Transaction,
        _input: usize,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(anchor_tx.txid().as_ref());
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_channel_announcement_with_funding_key(
        &self,
        _msg: &UnsignedChannelAnnouncement,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        let sig_bytes = Self::invert_bytes(&[0x42; 64]);
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }

    fn sign_splicing_funding_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        input_value: u64,
        _secp_ctx: &Secp256k1<secp256k1::All>,
    ) -> Result<Signature, ()> {
        self.sign_counter.fetch_add(1, Ordering::SeqCst);
        // Use transaction bytes + input_index + input_value for deterministic "signature"
        let mut input_bytes = Vec::new();
        input_bytes.extend_from_slice(tx.compute_txid().as_ref());
        input_bytes.extend_from_slice(&input_index.to_le_bytes());
        input_bytes.extend_from_slice(&input_value.to_le_bytes());
        let sig_bytes = Self::invert_bytes(&input_bytes);
        Ok(Signature::from_compact(&sig_bytes[..64]).unwrap())
    }
}

#[test]
fn test_wrapped_channel_signer_returns_outer_id() {
    let mock = MockSigner::new();
    let inner_id = mock.channel_keys_id();
    let outer_id = [99u8; 32];
    let wrapped = WrappedChannelSigner::new(Box::new(mock));
    wrapped.set_outer_channel_keys_id(outer_id);

    // Should return our outer id, not inner id
    assert_eq!(wrapped.channel_keys_id(), outer_id);
    assert_ne!(wrapped.channel_keys_id(), inner_id);
}

#[test]
fn test_wrapped_channel_signer_delegates_all_operations() {
    let counter = Rc::new(AtomicU64::new(0));
    let mock_ref = MockSigner::new();
    let mock_wrapped = MockSigner::with_counter(counter.clone());
    let outer_id = [99u8; 32];
    let mut wrapped = WrappedChannelSigner::new(Box::new(mock_wrapped));
    wrapped.set_outer_channel_keys_id(outer_id);

    // Create a dummy transaction to sign
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };

    // Sign with wrapper and verify mock
    let sig1 = wrapped.sign_holder_anchor_input(&tx, 0, &Secp256k1::new()).unwrap();
    let sig2 = mock_ref.sign_holder_anchor_input(&tx, 0, &Secp256k1::new()).unwrap();

    // Should get same "signature" (inverted bytes) from both
    assert_eq!(sig1, sig2);

    // Verify counter was incremented
    assert_eq!(counter.load(Ordering::SeqCst), 1);

    // Test all other operations
    assert_eq!(
        wrapped.get_per_commitment_point(42, &Secp256k1::new()),
        mock_ref.get_per_commitment_point(42, &Secp256k1::new())
    );
    assert_eq!(
        wrapped.release_commitment_secret(42),
        mock_ref.release_commitment_secret(42)
    );

    // Create channel parameters for testing
    let secp = Secp256k1::new();
    // Create test transaction parameters - just set up enough for the test to work
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: Vec::new(),
    };
    let funding_outpoint = lightning::chain::transaction::OutPoint { txid: tx.txid(), index: 0 };

    // Create test channel parameters
    // Create a temporary ChannelTransactionParameters to get DirectedChannelTransactionParameters
    let mut base_params = lightning::ln::chan_utils::ChannelTransactionParameters {
        holder_pubkeys: mock_ref.pubkeys().clone(),
        holder_selected_contest_delay: 42,
        is_outbound_from_holder: true,
        counterparty_parameters: Some(lightning::ln::chan_utils::CounterpartyChannelTransactionParameters {
            pubkeys: mock_ref.pubkeys().clone(),
            selected_contest_delay: 42,
        }),
        funding_outpoint: Some(funding_outpoint),
        channel_type_features: ChannelTypeFeatures::empty(),
    };
    // Set late parameters to allow as_holder_broadcastable to work
    base_params.funding_outpoint = Some(funding_outpoint);
    let channel_parameters = base_params.as_holder_broadcastable();

    // Test validate_holder_commitment
    let commitment_tx = CommitmentTransaction::new_with_auxiliary_htlc_data::<()>(
        0, // commitment_number
        1000, // to_broadcaster_value_sat
        1000, // to_countersignatory_value_sat
        mock_ref.pubkeys().funding_pubkey,
        mock_ref.pubkeys().funding_pubkey,
        lightning::ln::chan_utils::TxCreationKeys {
            per_commitment_point: mock_ref.pubkeys().funding_pubkey,
            revocation_key: lightning::ln::channel_keys::RevocationKey(mock_ref.pubkeys().funding_pubkey),
            broadcaster_htlc_key: lightning::ln::channel_keys::HtlcKey(mock_ref.pubkeys().funding_pubkey),
            countersignatory_htlc_key: lightning::ln::channel_keys::HtlcKey(mock_ref.pubkeys().funding_pubkey),
            broadcaster_delayed_payment_key: lightning::ln::channel_keys::DelayedPaymentKey(mock_ref.pubkeys().funding_pubkey),
        },
        0, // feerate_per_kw
        &mut vec![], // htlcs_with_aux
        &channel_parameters,
    );

    let holder_tx = HolderCommitmentTransaction::new(
        commitment_tx.clone(),
        Signature::from_compact(&[0x42; 64]).unwrap(),
        vec![],
        &mock_ref.pubkeys().funding_pubkey,
        &mock_ref.pubkeys().funding_pubkey,
    );

    assert_eq!(
        wrapped.validate_holder_commitment(&holder_tx, Vec::new()),
        mock_ref.validate_holder_commitment(&holder_tx, Vec::new())
    );

    // Test provide_channel_parameters
    let mut mock_ref = mock_ref;  // Make mutable for provide_channel_parameters
    let channel_params = ChannelTransactionParameters {
        holder_pubkeys: mock_ref.pubkeys().clone(),
        counterparty_parameters: None,
        is_outbound_from_holder: true,
        channel_type_features: ChannelTypeFeatures::empty(),
        funding_outpoint: None,
        holder_selected_contest_delay: 42,
    };
    assert_eq!(
        wrapped.provide_channel_parameters(&channel_params),
        mock_ref.provide_channel_parameters(&channel_params)
    );

    // Test sign_counterparty_commitment
    assert_eq!(
        wrapped.sign_counterparty_commitment(&commitment_tx, Vec::new(), Vec::new(), &secp),
        mock_ref.sign_counterparty_commitment(&commitment_tx, Vec::new(), Vec::new(), &secp)
    );

    // Test sign_holder_commitment
    assert_eq!(
        wrapped.sign_holder_commitment(&holder_tx, &secp),
        mock_ref.sign_holder_commitment(&holder_tx, &secp)
    );

    assert_eq!(
        wrapped.validate_counterparty_revocation(42, &SecretKey::from_slice(&[42; 32]).unwrap()),
        mock_ref.validate_counterparty_revocation(42, &SecretKey::from_slice(&[42; 32]).unwrap())
    );
    assert_eq!(
        wrapped.sign_justice_revoked_output(&tx, 0, 1000, &SecretKey::from_slice(&[42; 32]).unwrap(), &secp),
        mock_ref.sign_justice_revoked_output(&tx, 0, 1000, &SecretKey::from_slice(&[42; 32]).unwrap(), &secp)
    );
    let htlc = HTLCOutputInCommitment {
        offered: true,
        amount_msat: 1000,
        cltv_expiry: 42,
        payment_hash: PaymentHash([42; 32]),
        transaction_output_index: Some(0),
    };
    assert_eq!(
        wrapped.sign_justice_revoked_htlc(&tx, 0, 1000, &SecretKey::from_slice(&[42; 32]).unwrap(), &htlc, &secp),
        mock_ref.sign_justice_revoked_htlc(&tx, 0, 1000, &SecretKey::from_slice(&[42; 32]).unwrap(), &htlc, &secp)
    );
    let htlc_descriptor = HTLCDescriptor {
        channel_derivation_parameters: ChannelDerivationParameters {
            value_satoshis: 1000,
            keys_id: mock_ref.channel_keys_id(),
            transaction_parameters: channel_params,
        },
        commitment_txid: tx.txid(),
        per_commitment_number: 42,
        per_commitment_point: mock_ref.pubkeys().funding_pubkey,
        htlc: HTLCOutputInCommitment {
            offered: true,
            amount_msat: 1000,
            cltv_expiry: 42,
            payment_hash: PaymentHash([42; 32]),
            transaction_output_index: Some(0),
        },
        preimage: None,
        counterparty_sig: Signature::from_compact(&[0x42; 64]).unwrap(),
        feerate_per_kw: 0,
    };
    assert_eq!(
        wrapped.sign_holder_htlc_transaction(&tx, 0, &htlc_descriptor, &secp),
        mock_ref.sign_holder_htlc_transaction(&tx, 0, &htlc_descriptor, &secp)
    );
    assert_eq!(
        wrapped.sign_counterparty_htlc_transaction(&tx, 0, 1000, &mock_ref.pubkeys().funding_pubkey, &htlc, &secp),
        mock_ref.sign_counterparty_htlc_transaction(&tx, 0, 1000, &mock_ref.pubkeys().funding_pubkey, &htlc, &secp)
    );
    let closing_tx = ClosingTransaction::new(
        1000,
        1000,
        ScriptBuf::new(),
        ScriptBuf::new(),
        OutPoint { txid: tx.txid(), vout: 0 },
    );
    assert_eq!(
        wrapped.sign_closing_transaction(&closing_tx, &secp),
        mock_ref.sign_closing_transaction(&closing_tx, &secp)
    );

    let msg = UnsignedChannelAnnouncement {
        node_id_1: NodeId::from_pubkey(&mock_ref.pubkeys().funding_pubkey),
        node_id_2: NodeId::from_pubkey(&mock_ref.pubkeys().funding_pubkey),
        bitcoin_key_1: NodeId::from_pubkey(&mock_ref.pubkeys().funding_pubkey),
        bitcoin_key_2: NodeId::from_pubkey(&mock_ref.pubkeys().funding_pubkey),
        chain_hash: [0u8; 32].into(),
        short_channel_id: 42,
        features: ChannelFeatures::empty(),
        excess_data: Vec::new(),
    };
    assert_eq!(
        wrapped.sign_channel_announcement_with_funding_key(&msg, &secp),
        mock_ref.sign_channel_announcement_with_funding_key(&msg, &secp)
    );

    // Test sign_splicing_funding_input
    assert_eq!(
        wrapped.sign_splicing_funding_input(&tx, 0, 1000, &secp),
        mock_ref.sign_splicing_funding_input(&tx, 0, 1000, &secp)
    );

    // Verify all operations were delegated (13 operations)
    assert_eq!(counter.load(Ordering::SeqCst), 13);
}

#[test]
fn test_wrapped_channel_signer_delegates_pubkeys() {
    let mock = MockSigner::new();
    let pubkeys = mock.pubkeys().clone();
    let outer_id = [99u8; 32];
    let wrapped = WrappedChannelSigner::new(Box::new(mock));
    wrapped.set_outer_channel_keys_id(outer_id);

    // Should return same pubkeys as inner
    assert_eq!(wrapped.pubkeys(), &pubkeys);
}

#[test]
fn test_wrapped_channel_signer_uses_inner_id_when_outer_not_set() {
    let mock = MockSigner::new();
    let inner_id = mock.channel_keys_id();
    let wrapped = WrappedChannelSigner::new(Box::new(mock));
    // Don't set outer_id
    assert_eq!(wrapped.channel_keys_id(), inner_id);
}
