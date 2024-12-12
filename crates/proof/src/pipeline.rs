use kona_driver::{DriverPipeline, PipelineCursor};
use kona_preimage::CommsClient;
use kona_proof::{l1::OracleL1ChainProvider, l2::OracleL2ChainProvider, FlushableCache};
use core::fmt::Debug;
use alloc::{boxed::Box, sync::Arc};
use kona_derive::{
    attributes::StatefulAttributesBuilder,
    errors::PipelineErrorKind,
    pipeline::{DerivationPipeline, PipelineBuilder},
    sources::{EthereumDataSource},
    stages::{
        AttributesQueue, BatchProvider, BatchStream, ChannelProvider, ChannelReader, FrameQueue,
        L1Retrieval, L1Traversal,
    },
    traits::{BlobProvider, OriginProvider, Pipeline, SignalReceiver},
    types::{PipelineResult, Signal, StepResult},
};
use eigenda::traits::EigenDABlobProvider;
use eigenda::eigenda::EigenDADataSource;
use eigenda::eigenda_blobs::EigenDABlobSource;
use op_alloy_genesis::{RollupConfig, SystemConfig};

/// An oracle-backed payload attributes builder for the `AttributesQueue` stage of the derivation
/// pipeline.
pub type OracleAttributesBuilder<O> =
    StatefulAttributesBuilder<OracleL1ChainProvider<O>, OracleL2ChainProvider<O>>;

/// An oracle-backed attributes queue for the derivation pipeline.
pub type OracleAttributesQueue<DAP, O> = AttributesQueue<
    BatchProvider<
        BatchStream<
            ChannelReader<
                ChannelProvider<
                    FrameQueue<L1Retrieval<DAP, L1Traversal<OracleL1ChainProvider<O>>>>,
                >,
            >,
            OracleL2ChainProvider<O>,
        >,
        OracleL2ChainProvider<O>,
    >,
    OracleAttributesBuilder<O>,
>;

/// An oracle-backed Ethereum data source.
pub type OracleDataProvider<O, B, A> = EigenDADataSource<OracleL1ChainProvider<O>, B, A>;

pub type OracleDerivationPipeline<O, B, A> = DerivationPipeline<
    OracleAttributesQueue<OracleDataProvider<O, B, A>, O>,
    OracleL2ChainProvider<O>,
>;

/// An oracle-backed derivation pipeline.
#[derive(Debug)]
pub struct OraclePipeline<O, B, A>
where
    O: CommsClient + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    A: EigenDABlobProvider + Send + Sync + Debug + Clone,
{
    /// The internal derivation pipeline.
    pub pipeline: OracleDerivationPipeline<O, B, A>,
    pub caching_oracle: Arc<O>,
}

impl<O, B, A> OraclePipeline<O, B, A>
where
    O: CommsClient + FlushableCache + FlushableCache + Send + Sync + Debug,
    B: BlobProvider + Send + Sync + Debug + Clone,
    A: EigenDABlobProvider + Send + Sync + Debug + Clone,
{
    /// Constructs a new oracle-backed derivation pipeline.
    pub fn new(
        cfg: Arc<RollupConfig>,
        sync_start: PipelineCursor,
        caching_oracle: Arc<O>,
        blob_provider: B,
        chain_provider: OracleL1ChainProvider<O>,
        l2_chain_provider: OracleL2ChainProvider<O>,
        eigenda_blob_provider: A,
    ) -> Self {
        let attributes = StatefulAttributesBuilder::new(
            cfg.clone(),
            l2_chain_provider.clone(),
            chain_provider.clone(),
        );
        let dap = EthereumDataSource::new_from_parts(chain_provider.clone(), blob_provider, &cfg);
        let eigenda_blob_source = EigenDABlobSource::new(eigenda_blob_provider);
        let dap =  EigenDADataSource::new(dap, eigenda_blob_source);

        let pipeline = PipelineBuilder::new()
            .rollup_config(cfg)
            .dap_source(dap)
            .l2_chain_provider(l2_chain_provider)
            .chain_provider(chain_provider)
            .builder(attributes)
            .origin(sync_start.origin())
            .build();
        Self { pipeline, caching_oracle }
    }
}