use std::str::FromStr;
use std::time::Duration;

use flex_error::DisplayError;
use tendermint::{block::Height, trust_threshold::TrustThresholdFraction, Hash, Time};
use tendermint_light_client::{
    components::{
        clock::{Clock, FixedClock},
        io::{AtHeight, Io, IoError, ProdIo},
    },
    predicates::ProdPredicates,
    state::State,
    store::memory::MemoryStore,
    types::{LightBlock, PeerId},
    verifier::{
        options::Options, predicates::VerificationPredicates, types::Status, ProdVerifier, Verdict,
        Verifier,
    },
};
use tendermint_light_client_verifier::errors::VerificationErrorDetail;
use tendermint_rpc as rpc;

// [[chains]]
// id = 'osmosis-1'
// rpc_addr = 'http://127.0.0.1:26657'
// grpc_addr = 'http://127.0.0.1:9090'
// websocket_addr = 'ws://127.0.0.1:26657/websocket'
// rpc_timeout = '10s'
// account_prefix = 'osmo'
// key_name = 'osmosis'
// address_type = { derivation = 'cosmos' }
// store_prefix = 'ibc'
// default_gas = 5000000
// max_gas = 15000000
// gas_price = { price = 0.0026, denom = 'uosmo' }
// gas_multiplier = 1.1
// max_msg_num = 20
// max_tx_size = 209715
// clock_drift = '20s'
// max_block_time = '10s'
// trusting_period = '10days'
// memo_prefix = 'Osmosis Docs Rocks'
// trust_threshold = { numerator = '1', denominator = '3' }
// [chains.packet_filter]
// policy = 'allow'
// list = [
//   ['transfer', 'channel-0'], # cosmoshub-4
// ]

// https://services.kjnodes.com/mainnet/osmosis/public-rpc/

use flex_error::define_error;

use tendermint_light_client::verifier::errors::VerificationError;

define_error! {
    Error {
        Io
            [ IoError ]
            | _ | { "I/O error" },

        HeightMismatch
            {
                given: Height,
                found: Height,
            }
            | e | {
                format_args!("height mismatch: given = {0}, found = {1}",
                    e.given, e.found)
            },

        HashMismatch
            {
                given: Hash,
                found: Hash,
            }
            | e | {
                format_args!("hash mismatch: given = {0}, found = {1}",
                    e.given, e.found)
            },

        InvalidLightBlock
            [ VerificationError ]
            | _ | { "invalid light block" },

        NoTrustedStateInStore
            | _ | { "no trusted state in store" },

        NoInitialTrustedState
            | _ | { "no initial trusted state" },

        EmptyWitnessList
            | _ | { "empty witness list" },

        TargetLowerThanTrustedState
            {
                target_height: Height,
                trusted_height: Height,
            }
            | e | {
                format_args!("target height ({0}) is lower than trusted state ({1})",
                    e.target_height, e.trusted_height)
            },

        TrustedStateOutsideTrustingPeriod
            {
                trusted_state: Box<LightBlock>,
                options: Options,
            }
            | _ | {
                format_args!("trusted state outside of trusting period")
            },

        InvalidLightBlockDetail
            [ DisplayError<VerificationErrorDetail> ]
            | _ | { "invalid light block" },

    }
}

pub struct CosmosRoute {
    io: ProdIo,
}

impl CosmosRoute {
    pub fn new(io: &ProdIo) -> Self {
        Self { io: io.clone() }
    }

    pub fn fetch_light_block(&self, height: Height) -> Result<LightBlock, IoError> {
        self.io.fetch_light_block(AtHeight::At(height))
    }

    pub fn latest_height(&self) -> Result<Height, IoError> {
        let signed_header = self.io.fetch_signed_header(AtHeight::Highest)?;
        Ok(Height::from(signed_header.header.height.value() as u32 - 1))
    }

    pub fn verify_to_highest(&self, light_client: &mut LightClient) -> Result<LightBlock, Error> {
        let latest_height = self.latest_height().map_err(Error::io)?;

        self.verify_to_target(latest_height, light_client)
    }

    pub fn verify_to_target(
        &self,
        target_height: Height,
        light_client: &mut LightClient,
    ) -> Result<LightBlock, Error> {
        // Let's first look in the store to see whether
        // we have already successfully verified this block.
        if let Some(light_block) = light_client
            .state
            .light_store
            .get_trusted_or_verified(target_height)
        {
            return Ok(light_block);
        }

        // Get the highest trusted state
        let highest = light_client
            .state
            .light_store
            .highest_trusted_or_verified_before(target_height)
            .or_else(|| light_client.state.light_store.lowest_trusted_or_verified())
            .ok_or_else(Error::no_initial_trusted_state)?;

        if target_height >= highest.height() {
            // Perform forward verification with bisection
            self.verify_forward(target_height, light_client)
        } else {
            // Perform sequential backward verification
            // self.verify_backward(target_height, state)

            return Err(Error::target_lower_than_trusted_state(
                target_height,
                highest.height(),
            ));
        }
    }

    fn verify_forward(
        &self,
        target_height: Height,
        light_client: &mut LightClient,
    ) -> Result<LightBlock, Error> {
        let mut current_height = target_height;

        loop {
            let current_block = self.fetch_light_block(current_height).map_err(Error::io)?;
            let trusted_height =
                light_client.verify_light_block(target_height, current_height, &current_block)?;
            println!("new trusted height: {:?}", trusted_height);
            if trusted_height == target_height {
                // TODO
                return Ok(current_block);
            }

            // Compute the next height to fetch and verify
            current_height =
                Self::basic_bisecting_schedule(trusted_height, current_height, target_height);
        }
    }
    pub fn basic_bisecting_schedule(
        trusted_height: Height,
        current_height: Height,
        target_height: Height,
    ) -> Height {
        if trusted_height == current_height {
            // We can't go further back, so let's try to verify the target height again,
            // hopefully we have enough trust in the store by now.
            target_height
        } else {
            // Pick a midpoint H between `trusted_height <= H <= current_height`.
            Self::midpoint(trusted_height, current_height)
        }
    }

    fn midpoint(low: Height, high: Height) -> Height {
        (low.value() + (high.value() + 1 - low.value()) / 2)
            .try_into()
            .unwrap() // Will panic if midpoint is higher than i64::MAX
    }
}

pub struct LightClient {
    pub options: Options,
    pub clock: Box<dyn Clock>,
    pub verifier: Box<dyn Verifier>,
    pub predicates: Box<dyn VerificationPredicates<Sha256 = tendermint::crypto::default::Sha256>>,
    pub state: State,
}

impl LightClient {
    /// Constructs a new light client
    pub fn new(
        options: Options,
        verifier: Box<dyn Verifier>,
        predicates: Box<dyn VerificationPredicates<Sha256 = tendermint::crypto::default::Sha256>>,
    ) -> Self {
        Self {
            options,
            clock: Box::new(FixedClock::new(Time::now())),
            verifier,
            predicates,
            state: State::new(MemoryStore::new()),
        }
    }

    fn validate(&self, light_block: &LightBlock) -> Result<(), Error> {
        let header = &light_block.signed_header.header;
        let now = self.clock.now();

        self.predicates
            .is_within_trust_period(header.time, self.options.trusting_period, now)
            .map_err(Error::invalid_light_block)?;

        self.predicates
            .is_header_from_past(header.time, self.options.clock_drift, now)
            .map_err(Error::invalid_light_block)?;

        self.predicates
            .validator_sets_match(
                &light_block.validators,
                light_block.signed_header.header.validators_hash,
            )
            .map_err(Error::invalid_light_block)?;

        self.predicates
            .next_validators_match(
                &light_block.next_validators,
                light_block.signed_header.header.next_validators_hash,
            )
            .map_err(Error::invalid_light_block)?;

        Ok(())
    }

    pub fn highest_trusted_or_verified(&self) -> Option<LightBlock> {
        self.state.light_store.highest_trusted_or_verified()
    }

    pub fn is_within_trust_period(
        light_block: &LightBlock,
        trusting_period: Duration,
        now: Time,
    ) -> bool {
        let header_time = light_block.signed_header.header.time;
        match now - trusting_period {
            Ok(start) => header_time > start,
            Err(_) => false,
        }
    }

    pub fn verify_light_block(
        &mut self,
        target_height: Height,
        current_height: Height,
        current_block: &LightBlock,
    ) -> Result<Height, Error> {
        let mut current_block = current_block.clone();
        let mut status = Status::Unverified;

        let block = self.state.light_store.get_non_failed(current_height);

        if let Some(block) = block {
            current_block = block.0;
            status = block.1;
        } else {
            self.state
                .light_store
                .insert(current_block.clone(), Status::Unverified);
        }

        let now = self.clock.now();

        // Get the latest trusted state
        let trusted_block = self
            .state
            .light_store
            .highest_trusted_or_verified_before(target_height)
            .ok_or_else(Error::no_initial_trusted_state)?;

        if target_height < trusted_block.height() {
            return Err(Error::target_lower_than_trusted_state(
                target_height,
                trusted_block.height(),
            ));
        }

        // Check invariant [LCV-INV-TP.1]
        if !Self::is_within_trust_period(&trusted_block, self.options.trusting_period, now) {
            return Err(Error::trusted_state_outside_trusting_period(
                Box::new(trusted_block),
                self.options,
            ));
        }

        // Log the current height as a dependency of the block at the target height
        self.state.trace_block(target_height, current_height);

        // If the trusted state is now at a height equal to the target height, we are done.
        // [LCV-DIST-LIFE.1]
        if target_height == trusted_block.height() {
            return Ok(trusted_block.height());
        }

        // Validate and verify the current block
        let verdict = self.verifier.verify_update_header(
            current_block.as_untrusted_state(),
            trusted_block.as_trusted_state(),
            &self.options,
            now,
        );

        match verdict {
            Verdict::Success => {
                // Verification succeeded, add the block to the light store with
                // the `Verified` status or higher if already trusted.
                let new_status = Status::most_trusted(Status::Verified, status);
                self.state.light_store.update(&current_block, new_status);

                // Log the trusted height as a dependency of the block at the current height
                self.state
                    .trace_block(current_height, trusted_block.height());
            }
            Verdict::Invalid(e) => {
                // Verification failed, add the block to the light store with `Failed` status,
                // and abort.
                self.state
                    .light_store
                    .update(&current_block, Status::Failed);

                return Err(Error::invalid_light_block_detail(e));
            }
            Verdict::NotEnoughTrust(_) => {
                // The current block cannot be trusted because of a missing overlap in the
                // validator sets. Add the block to the light store with
                // the `Unverified` status. This will engage bisection in an
                // attempt to raise the height of the highest trusted state
                // until there is enough overlap.
                self.state
                    .light_store
                    .update(&current_block, Status::Unverified);
            }
        }

        let trusted_height = self
            .state
            .light_store
            .highest_trusted_or_verified_before(target_height)
            .map(|lb| lb.height())
            .unwrap();
        Ok(trusted_height)
    }
}

fn main() -> Result<(), Error> {
    println!("Hello, world!");

    // $ ~/go/bin/osmosisd status --node tcp://178.63.130.196:26657
    // {"NodeInfo":{"protocol_version":{"p2p":"8","block":"11","app":"0"},"id":"c1023ca3f1f17f69fb01146e6b10f686a838d678","listen_addr":"tcp://0.0.0.0:26656","network":"osmosis-1","version":"0.37.4","channels":"40202122233038606100","moniker":"osmosis","other":{"tx_index":"on","rpc_address":"tcp://0.0.0.0:26657"}},"SyncInfo":{"latest_block_hash":"C78BE0B00776CD49F1F1724F6153C7EE6EC635AD78DCB6BC9FF1F39639D4D253","latest_app_hash":"E809B2EC4FEF97BF2AC86DABFB4DBB0BE945DCF151BD885EC66D1D5D8034835B","latest_block_height":"19802391","latest_block_time":"2024-08-24T15:19:26.477987149Z","earliest_block_hash":"C8DC787FAAE0941EF05C75C3AECCF04B85DFB1D4A8D054A463F323B0D9459719","earliest_app_hash":"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855","earliest_block_height":"1","earliest_block_time":"2021-06-18T17:00:00Z","catching_up":false},"ValidatorInfo":{"Address":"9648374F6970E7B04ADAC786CC2968A5F5452516","PubKey":{"type":"tendermint/PubKeyEd25519","value":"f0U47TWGpKcyIAzSIwzCHLZIJXHSq8DjWp9+t8QERh8="},"VotingPower":"0"}}
    let rpc_client = rpc::HttpClient::builder("http://178.63.142.152:26657".try_into().unwrap())
        .build()
        .unwrap();
    let peer_id = PeerId::from_str("c89fa4604b848ebe76004df5a698cb3ad9e4cfda").unwrap();
    let io = ProdIo::new(peer_id, rpc_client.clone(), None);

    let route = CosmosRoute::new(&io);

    let options = Options {
        trust_threshold: TrustThresholdFraction::ONE_THIRD,
        trusting_period: Duration::from_secs(10 * 24 * 60 * 60),
        clock_drift: Duration::from_secs(20),
    };

    let mut light_client = LightClient::new(
        options,
        Box::<ProdVerifier>::default(),
        Box::new(ProdPredicates),
    );

    // route
    let trusted_state = route.fetch_light_block(Height::from(19693151u32)).unwrap();
    println!(
        "trusted_state last_commit_hash: {:?}, data_hash: {:?}",
        trusted_state.signed_header.header.last_commit_hash,
        trusted_state.signed_header.header.data_hash
    );

    light_client.validate(&trusted_state).unwrap();
    light_client
        .state
        .light_store
        .insert(trusted_state, Status::Trusted);
    println!(
        "set trusted height: {:?}",
        light_client.highest_trusted_or_verified().unwrap().height()
    );

    // route
    let latest_height = route.latest_height().unwrap();
    println!("latest_height: {:?}", latest_height);
    let light_block = route.verify_to_highest(&mut light_client).unwrap();
    println!("light_block height: {:?}", light_block.height());

    Ok(())
}
