//! Experimental Tx re-broadcaster for ethers-rs txns

use std::{
    fmt::{Debug, Display},
    future::Future,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use ethers::{
    prelude::{signer::SignerMiddlewareError, SignerMiddleware},
    providers::{FilterWatcher, Middleware, PendingTransaction, ProviderError},
    signers::Signer,
    types::{
        transaction::eip2718::TypedTransaction, Address, Block, Bytes, Signature, Transaction,
        TransactionReceipt, TxHash, H256, U256, U64,
    },
};
use futures::StreamExt;

/// too lazy to write "pin box fut" over and over
type Pbf<'a, M, T> = Pin<Box<dyn Future<Output = Result<T, <M as Middleware>::Error>> + 'a>>;

/// A Tx Manager. Handles re-broadcasting a pending tx repeatedly, and checking
/// if another tx confirms at the same nonce.
///
/// As a future, it will resolve to either
/// - An error from the underlying middleware
/// - Ok(Some(receipt)) - when this TX has confirmed and the receipt is available
///
/// If the transaction appears to have been dropped from the mempool, this
/// future will rebroadcast it. This will repeat until either the tx is
/// confirmed, or the account nonce.
///
/// Polling for the nonce increase happens approximately every block
///
///
#[pin_project::pin_project]
#[must_use = "Futures do nothing unless polled"]
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

impl<'a, M> Debug for TxMan<'a, M>
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
            // skip the blocks stream
            .finish()
    }
}

impl<M> Display for TxMan<'_, M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tx for {:?}", self.hash)
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
    GettingNonce {
        head: Pbf<'a, M, U64>,
        nonce: Pbf<'a, M, U256>,
    },
    Seeking {
        lower_bound: U64,
        height: U64,
        block: Pbf<'a, M, Option<Block<Transaction>>>,
    },
    FetchingReceipt {
        tx_hash: TxHash,
        receipt: Pbf<'a, M, Option<TransactionReceipt>>,
    },
    Complete,
    Delaying {
        delay: Pin<Box<tokio::time::Sleep>>,
        next_state: Box<Option<Self>>,
    },
}

impl<'a, M> Debug for ManStates<'a, M>
where
    M: Middleware,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitialBroadcast(_) => write!(f, "InitialBroadcast"),
            Self::Rebroadcasting(_) => write!(f, "Rebroadcasting"),
            Self::WaitingForReceipt(_) => write!(f, "WaitingForReceipt"),
            Self::FetchingReceipt { .. } => write!(f, "FetchingReceipt"),
            Self::GettingNonce { .. } => write!(f, "GettingNonce"),
            Self::Seeking { .. } => write!(f, "Seeking"),
            Self::Complete => write!(f, "Complete"),
            Self::Delaying { next_state, .. } => {
                f.debug_tuple("Delaying").field(next_state).finish()
            }
        }
    }
}

impl<'a, M> std::future::Future for TxMan<'a, M>
where
    M: Middleware,
{
    type Output = Result<TransactionReceipt, M::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.state {
            // after broadcast we go into waiting for receipt.
            ManStates::InitialBroadcast(fut) | ManStates::Rebroadcasting(fut) => {
                match futures::ready!(fut.as_mut().poll(cx)) {
                    Ok(pending) => {
                        // we set this low so that the delay is low
                        let pending = pending.interval(Duration::from_secs(1));
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
                    (_, Poll::Ready(res)) => match res {
                        Ok(Some(receipt)) => Poll::Ready(Ok(receipt)),
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
                    (Poll::Ready(_), _) => {
                        *this.state = ManStates::GettingNonce {
                            head: Box::pin(this.provider.get_block_number()),
                            nonce: Box::pin(
                                this.provider.get_transaction_count(*this.sender, None),
                            ),
                        };
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    // Nothing to see here
                    (Poll::Pending, Poll::Pending) => Poll::Pending,
                }
            }
            // We get the nonce to
            ManStates::GettingNonce { head, nonce } => {
                match (head.as_mut().poll(cx), nonce.as_mut().poll(cx)) {
                    (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => {
                        *this.state = ManStates::Complete;
                        Poll::Ready(Err(e))
                    }

                    (Poll::Ready(Ok(height)), Poll::Ready(Ok(nonce))) => {
                        if nonce >= *this.nonce {
                            *this.state = ManStates::Seeking {
                                lower_bound: height - 15,
                                height,
                                block: this.provider.get_block_with_txs(height),
                            };
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        } else {
                            *this.state = ManStates::Rebroadcasting(Box::pin(
                                this.provider
                                    .send_raw_transaction(this.serialized_tx.clone()),
                            ));
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                    _ => Poll::Pending,
                }
            }
            ManStates::Seeking {
                lower_bound,
                height,
                block,
            } => match block.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => {
                    *this.state = ManStates::Complete;
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Ok(None)) => {
                    *this.state = ManStates::Delaying {
                        delay: Box::pin(tokio::time::sleep(Duration::from_secs(2))),
                        next_state: Box::new(Some(ManStates::GettingNonce {
                            head: Box::pin(this.provider.get_block_number()),
                            nonce: Box::pin(
                                this.provider.get_transaction_count(*this.sender, None),
                            ),
                        })),
                    };
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Ok(Some(block))) => {
                    if let Some(tx) = block.transactions.iter().find(|tx| tx.nonce == *this.nonce) {
                        *this.state = ManStates::FetchingReceipt {
                            tx_hash: tx.hash,
                            receipt: this.provider.get_transaction_receipt(tx.hash),
                        };
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    } else {
                        let height = *height - 1;
                        *this.state = ManStates::Seeking {
                            lower_bound: *lower_bound,
                            height,
                            block: Box::pin(this.provider.get_block_with_txs(height)),
                        };
                        Poll::Pending
                    }
                }
                Poll::Pending => Poll::Pending,
            },
            ManStates::FetchingReceipt { tx_hash, receipt } => {
                match futures::ready!(receipt.as_mut().poll(cx)) {
                    Ok(Some(receipt)) => {
                        *this.state = ManStates::Complete;
                        Poll::Ready(Ok(receipt))
                    }
                    Ok(None) => {
                        *this.state = ManStates::Delaying {
                            delay: Box::pin(tokio::time::sleep(Duration::from_secs(2))),
                            next_state: Box::new(Some(ManStates::FetchingReceipt {
                                tx_hash: *tx_hash,
                                receipt: this.provider.get_transaction_receipt(*tx_hash),
                            })),
                        };
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => {
                        *this.state = ManStates::Complete;
                        Poll::Ready(Err(e))
                    }
                }
            }
            ManStates::Complete => panic!("polled after completion"),
            ManStates::Delaying { delay, next_state } => {
                futures::ready!(delay.as_mut().poll(cx));
                *this.state = next_state.take().expect("implementation error");
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
