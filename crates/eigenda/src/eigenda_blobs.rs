//! Blob Data Source

use crate::eigenda::EigenDADataSource;
use crate::traits::EigenDABlobProvider;
use crate::eigenda_data::EigenDABlobData;

use kona_derive::{
    errors::{BlobProviderError, PipelineError},
    traits::{BlobProvider, ChainProvider, DataAvailabilityProvider},
    types::PipelineResult,
};
use alloc::{boxed::Box, string::ToString, vec::Vec};
use alloy_primitives::{Address, Bytes};
use async_trait::async_trait;

use op_alloy_protocol::{BlockInfo, Frame, DERIVATION_VERSION_0};

/// A data iterator that reads from a blob.
#[derive(Debug, Clone)]
pub struct EigenDABlobSource<B>
where
    B: EigenDABlobProvider + Send,
{
    /// Fetches blobs.
    pub altda_fetcher: B,
    /// EigenDA blobs.
    pub data: Vec<EigenDABlobData>,
    /// Whether the source is open.
    pub open: bool,
}

impl<B> EigenDABlobSource<B>
where
    B: EigenDABlobProvider + Send,
{
    /// Creates a new blob source.
    pub const fn new(
        altda_fetcher: B,
    ) -> Self {
        Self {
            altda_fetcher,
            data: Vec::new(),
            open: false,
        }
    }

    /// Loads blob data into the source if it is not open.
    async fn load_blobs(&mut self, altDACommitment: &Bytes) -> Result<(), BlobProviderError> {
        if self.open {
            return Ok(());
        }

        info!(target: "eigenda-blobsource", "going to fetch through altda fetcher");
        // it should use self.altda_fetcher to get the blob
        let data = self.altda_fetcher.get_blob(altDACommitment).await;
        match data {
            Ok(data) => {
                self.open = true;
                let mut new_blob = data.clone();
                // new_blob.truncate(data.len()-1);
                let eigenda_blob = EigenDABlobData{ blob:new_blob } ;
                self.data.push(eigenda_blob);
                
                info!(target: "eigenda-blobsource", "load_blobs {:?}", self.data);

                Ok(())
            },
            Err(e) => {
                self.open = true;
                return Ok(())
            
            },
        }   
    }

    fn next_data(&mut self) -> Result<EigenDABlobData, PipelineResult<Bytes>> {
        info!(target: "eigenda-blobsource", "self.data.is_empty() {:?}", self.data.is_empty());

        if self.data.is_empty() {
            return Err(Err(PipelineError::Eof.temp()));
        }
        Ok(self.data.remove(0))
    }

    pub async fn next(&mut self, altDACommitment: &Bytes) -> PipelineResult<Bytes> {
        info!(target: "eigenda-blobsource", "next");
        self.load_blobs(altDACommitment).await?;
        info!(target: "eigenda-blobsource", "next 1");
        let next_data = match self.next_data() {
            Ok(d) => d,
            Err(e) => return e,
        };
        info!(target: "eigenda-blobsource", "next 2");
        // Decode the blob data to raw bytes.
        // Otherwise, ignore blob and recurse next.
        match next_data.decode() {
            Ok(d) => {
                info!(target: "eigenda-blobsource", "next 3");
                Ok(d)
            },
            Err(_) => {
                warn!(target: "blob-source", "Failed to decode blob data, skipping");
                panic!()
                // todo need to add recursion
                // self.next(altDACommitment).await
            }
        }
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.open = false;
    }
}
