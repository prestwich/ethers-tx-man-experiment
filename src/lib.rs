use std::{fmt::Display, future::Future, pin::Pin, task::Poll, time::Duration};

use ethers::{
    prelude::{signer::SignerMiddlewareError, SignerMiddleware},
    providers::{FilterWatcher, Middleware, PendingTransaction, ProviderError},
    signers::Signer,
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Signature, TransactionReceipt,
        TxHash, H256, U256,
    },
};
use futures::StreamExt;
use tokio::select;

/// too lazy to write "pin box fut" over and over
type Pbf<'a, M, T> = Pin<Box<dyn Future<Output = Result<T, <M as Middleware>::Error>> + 'a>>;

/// A Tx Manager. Handles re-broadcasting a pending tx repeatedly, and checking
/// if another tx confirms at the same nonce.
///
/// As a future, it will resolve to either
/// - An error from the underlying middleware
/// - Ok(None) - when another tx has confirmed at the same nonce
/// - Ok(Some(receipt)) - when this TX has confirmed and the receipt is available
///
/// If the transaction appears to have been dropped from the mempool, this
/// future will rebroadcast it. This will repeat until either the tx is
/// confirmed, or the account nonce.
///
/// Polling for the nonce increase happens approximately every block
#[pin_project::pin_project]
#[must_use = "Futures do nothing unless cloned"]
pub struct TxMan<'a, M>
where
    M: Middleware,
{
    /// Provider
    provider: &'a M,
    /// Serialized, signed transaction
    serialized_tx: Bytes,
    /// Sender of the TX
    sender: Address,
    /// TX Nonce
    nonce: U256,
    /// Hash of the TX
    hash: TxHash,
    /// Current State
    state: ManStates<'a, M>,
    /// stream of blocks
    blocks: FilterWatcher<'a, M::Provider, H256>,
}

impl<'a, M> std::fmt::Debug for TxMan<'a, M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxMan")
            .field("provider", &self.provider)
            .field("serialized_tx", &self.serialized_tx)
            .field("sender", &self.sender)
            .field("nonce", &self.nonce)
            .field("hash", &self.hash)
            .field("state", &self.state)
            .finish()
    }
}

impl<'a, M> TxMan<'a, M>
where
    M: Middleware,
{
    // TODO: consider allowing configuration of the pending transaction

    pub async fn new(
        provider: &'a M,
        tx: &TypedTransaction,
        sig: &Signature,
    ) -> Result<TxMan<'a, M>, M::Error> {
        let mut t = tx.clone();
        provider.fill_transaction(&mut t, None).await?;
        let nonce = *tx.nonce().expect("to be filled just above");
        let hash = tx.hash(sig);
        let serialized_tx = tx.rlp_signed(sig);
        let sender = sig
            .recover(tx.sighash())
            .map_err(|_| ProviderError::SignerUnavailable)
            .map_err(M::convert_err)?;
        let state =
            ManStates::InitialBroadcast(provider.send_raw_transaction(serialized_tx.clone()));
        let blocks = provider.watch_blocks().await?;

        Ok(Self {
            provider,
            serialized_tx,
            sender,
            nonce,
            hash,
            state,
            blocks,
        })
    }
}

impl<'a, M, S> TxMan<'a, SignerMiddleware<M, S>>
where
    M: Middleware,
    S: Signer,
{
    pub async fn from_signer(
        provider: &'a SignerMiddleware<M, S>,
        tx: &TypedTransaction,
    ) -> Result<TxMan<'a, SignerMiddleware<M, S>>, <SignerMiddleware<M, S> as Middleware>::Error>
    {
        let sig = provider
            .signer()
            .sign_transaction(tx)
            .await
            .map_err(SignerMiddlewareError::SignerError)?;
        Self::new(provider, tx, &sig).await
    }
}

pub enum ManStates<'a, M>
where
    M: Middleware,
{
    InitialBroadcast(Pbf<'a, M, PendingTransaction<'a, M::Provider>>),
    Rebroadcasting(Pbf<'a, M, PendingTransaction<'a, M::Provider>>),
    WaitingForReceipt(Pin<Box<PendingTransaction<'a, M::Provider>>>),
    GettingNonce(Pbf<'a, M, U256>),
    Complete,
}

impl<'a, M> std::fmt::Debug for ManStates<'a, M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitialBroadcast(_) => write!(f, "InitialBroadcast"),
            Self::Rebroadcasting(_) => write!(f, "Rebroadcasting"),
            Self::WaitingForReceipt(_) => write!(f, "WaitingForReceipt"),
            Self::GettingNonce(_) => write!(f, "GettingNonce"),
            Self::Complete => write!(f, "Complete"),
        }
    }
}

impl<'a, M> std::future::Future for TxMan<'a, M>
where
    M: Middleware,
{
    type Output = Result<Option<TransactionReceipt>, M::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            // after broadcast we go into waiting for receipt.
            ManStates::InitialBroadcast(fut) | ManStates::Rebroadcasting(fut) => {
                match futures::ready!(fut.as_mut().poll(cx)) {
                    // we don't actually want the pending transaction. we just
                    // want to go to receipt polling
                    Ok(pending) => {
                        *this.state = ManStates::WaitingForReceipt(Box::pin(pending));
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    // Errors are terminal.
                    Err(e) => {
                        *this.state = ManStates::Complete;
                        Poll::Ready(Err(e))
                    }
                }
            }
            // our waiting either resolves to timeout or to receipt
            ManStates::WaitingForReceipt(pending) => {
                match (this.blocks.poll_next_unpin(cx), pending.as_mut().poll(cx)) {
                    // pending resolved, regardless of sleep
                    (_, Poll::Ready(res)) => match res {
                        Ok(Some(receipt)) => Poll::Ready(Ok(Some(receipt))),
                        // No receipt
                        Ok(None) => {
                            *this.state = ManStates::Rebroadcasting(Box::pin(
                                this.provider
                                    .send_raw_transaction(this.serialized_tx.clone()),
                            ));
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        // Errors are terminal.
                        Err(e) => {
                            *this.state = ManStates::Complete;
                            Poll::Ready(Err(M::convert_err(e)))
                        }
                    },
                    // pending NOT resolved, sleep has
                    (Poll::Ready(_), _) => {
                        *this.state = ManStates::GettingNonce(Box::pin(
                            this.provider.get_transaction_count(*this.sender, None),
                        ));
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    // Nothing to see here
                    (Poll::Pending, Poll::Pending) => Poll::Pending,
                }
            }
            ManStates::GettingNonce(fut) => match futures::ready!(fut.as_mut().poll(cx)) {
                Ok(nonce) => {
                    if nonce >= *this.nonce {
                        *this.state = ManStates::Complete;
                        Poll::Ready(Ok(None))
                    } else {
                        *this.state = ManStates::Rebroadcasting(Box::pin(
                            this.provider
                                .send_raw_transaction(this.serialized_tx.clone()),
                        ));
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
                Err(e) => {
                    *this.state = ManStates::Complete;
                    Poll::Ready(Err(e))
                }
            },
            ManStates::Complete => panic!("polled after completion"),
        }
    }
}

impl<'a, M> TxMan<'a, M>
where
    M: Middleware,
{
    pub async fn spawn(self) -> Result<Option<TransactionReceipt>, M::Error> {
        // set up the initial pending
        let pending = PendingTransaction::new(self.hash, self.provider.provider());
        tokio::pin!(pending);

        loop {
            if let Ok(None) = self.provider.get_transaction(self.hash).await {
                *pending = self
                    .provider
                    .send_raw_transaction(self.serialized_tx.clone())
                    .await?;
            }

            select! {
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                res = &mut pending => {
                    match res {
                        Ok(None) => {
                            // indicates we believe it dropped.
                            // This will be addressed at top of loop
                            // no action needed here
                         }
                         Ok(Some(receipt)) => {
                            return Ok(Some(receipt))
                         }
                         Err(e) => {
                            return Err(M::convert_err(e))
                         }
                    }
                 }
            }
            let nonce = self
                .provider
                .get_transaction_count(self.sender, None)
                .await?;
            if nonce >= self.nonce {
                return Ok(None);
            }
        }
    }
}

/// Desires: resilient to mempool drops & to other txns at the same nonce
///
/// Data:
///
/// - Hold the serialized txn & its nonce
/// - Hold a provider
/// - Hold a `PendingTransaction` future
///
/// Behavior:
///
/// - select across pending and an `eth_getTransactionCount` call
/// - if the pending resolves to `Ok(None)`, rebraodcast it
/// - if the pending resolves to `Err(_)`, see if it's in the mempool
///   - if so, start a new pending it
///   - if not, rebroadcast it
/// - every 30 seconds poll the account nonce via `getTransactionCount`
///   - if >= tx nonce, end with `Ok(None)`
///      - (document that this indicates another tx confirmed at same nonce)
///   - else, continue waiting on the pending tx

impl<M> Display for TxMan<'_, M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tx for {:?}", self.hash)
    }
}
