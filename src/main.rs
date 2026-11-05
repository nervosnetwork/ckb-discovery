use ckb_discovery::handler::Handler;
use ckb_discovery::network::meta_info_to_addr;
use ckb_discovery_types::{CKBNetworkType, NodeMetaInfo, ReachableInfo};
use futures::StreamExt;
use log::{error, info, warn};
use nanoid::nanoid;
use p2p::secio::SecioKeyPair;
use p2p::service::TargetProtocol;
use p2p::yamux::Config;
use paho_mqtt as mqtt;
use paho_mqtt::QOS_1;
use std::env;
use std::error::Error;
use std::time::Duration;

/// Bounded MQTT input buffer. When full, newly arriving messages are dropped
/// instead of growing an unbounded queue; dial requests are re-broadcast.
const MQTT_STREAM_BUFFER: usize = 4096;
/// Bounded queue of discovered peers waiting to be published.
const REACHABLE_PUBLISH_QUEUE: usize = 8192;
/// Upper bound on simultaneous P2P sessions per network.
const MAX_CONNECTIONS: usize = 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env::set_var("RUST_LOG", "info");
    env_logger::init();

    let mqtt_url = env::var("MQTT_URL").unwrap_or("mqtt:1883".to_string());
    let mqtt_user = env::var("MQTT_USER").unwrap_or("ckb".to_string());
    let mqtt_pass = env::var("MQTT_PASS").unwrap_or("ckbdiscovery".to_string());

    let create_ops = mqtt::CreateOptionsBuilder::new()
        .server_uri(mqtt_url.clone())
        .max_buffered_messages(500)
        .client_id(format!("ckb-discovery-{}", nanoid!()))
        .finalize();

    let mut mqtt_client = mqtt::AsyncClient::new(create_ops).expect("Failed to create MQTT client");

    let conn_opts = mqtt::ConnectOptionsBuilder::new()
        .clean_start(true)
        // paho has second resolution; sub-second values are truncated and
        // coerced to 1 second, which makes brokers time the client out.
        .keep_alive_interval(Duration::from_secs(300))
        .automatic_reconnect(Duration::from_millis(500), Duration::from_millis(2000))
        .user_name(mqtt_user)
        .password(mqtt_pass)
        .properties(mqtt::properties![mqtt::PropertyCode::SessionExpiryInterval => 5000])
        .finalize();

    let topic = "peer/needs_dial";

    // The session is clean, so the broker drops subscriptions when the
    // connection is re-established. Restore them in the connected callback;
    // otherwise the probe keeps running but silently stops receiving work
    // until the process is restarted.
    let runtime = tokio::runtime::Handle::current();
    mqtt_client.set_connected_callback(move |client| {
        let client = client.clone();
        runtime.spawn(async move {
            match client.subscribe(topic, QOS_1).await {
                Ok(_) => info!("Subscribed to {}", topic),
                Err(err) => error!("Failed to subscribe to {}: {:?}", topic, err),
            }
        });
    });

    mqtt_client.connect(conn_opts).await?;

    info!("Connected to MQTT!");

    let mut mqtt_con = mqtt_client.get_stream(Some(MQTT_STREAM_BUFFER));

    // Also subscribe on the initial connection; the callback covers reconnects.
    mqtt_client.subscribe(topic, QOS_1).await?;

    // Publish discovered peers from one bounded queue instead of spawning a
    // task per peer. A single discovery reply can list up to 1000 peers, and
    // thousands of replies per cycle previously produced an unbounded number
    // of concurrent publish tasks.
    let (reachable_tx, mut reachable_rx) =
        tokio::sync::mpsc::channel::<ReachableInfo>(REACHABLE_PUBLISH_QUEUE);
    let reachable_client = mqtt_client.clone().to_owned();
    tokio::spawn(async move {
        while let Some(reachable) = reachable_rx.recv().await {
            let payload = match serde_json::to_vec(&reachable) {
                Ok(payload) => payload,
                Err(error) => {
                    error!("Failed to serialize reachable peer: {:?}", error);
                    continue;
                }
            };
            if let Err(error) = reachable_client
                .publish(mqtt::Message::new("peer/reachable", payload, QOS_1))
                .await
            {
                error!("Failed to publish reachable peer: {:?}", error);
            }
        }
    });

    let builder_fn = |network: CKBNetworkType| {
        let mqtt_ctx = mqtt_client.clone().to_owned();
        let mut service_builder = p2p::builder::ServiceBuilder::new();
        let handler = Handler::new(network, mqtt_ctx, reachable_tx.clone());

        for meta in handler.build_protocol_metas() {
            service_builder = service_builder.insert_protocol(meta);
        }
        service_builder
            .forever(true)
            .max_connection_number(MAX_CONNECTIONS)
            .handshake_type(SecioKeyPair::secp256k1_generated().into())
            .yamux_config(Config::default())
            .set_recv_buffer_size(24 * 1024 * 1024)
            .set_send_buffer_size(24 * 1024 * 1024)
            .timeout(Duration::from_secs(30))
            .build(handler)
    };

    let mut mirana_service = builder_fn(CKBNetworkType::Mirana);
    let mut pudge_service = builder_fn(CKBNetworkType::Pudge);

    let mirana_controller = mirana_service.control().to_owned();
    let pudge_controller = pudge_service.control().to_owned();

    let service_tx = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = mirana_service.run() => {

                },

                _ = pudge_service.run() => {

                },
            }
        }
    });

    let mqtt_tx = tokio::spawn(async move {
        while let Some(msg_opt) = mqtt_con.next().await {
            if let Some(msg) = msg_opt {
                match msg.topic() {
                    "peer/needs_dial" => {
                        // received a dial signal
                        match serde_json::from_slice::<NodeMetaInfo>(msg.payload()) {
                            Ok(node) => {
                                info!("Start dial {:?}", node);
                                let addrs = meta_info_to_addr(&node);
                                for addr in addrs.into_iter().flatten() {
                                    let res = match node.network {
                                        CKBNetworkType::Pudge => {
                                            pudge_controller
                                                .dial(addr.clone(), TargetProtocol::All)
                                                .await
                                        }
                                        CKBNetworkType::Mirana => {
                                            mirana_controller
                                                .dial(addr.clone(), TargetProtocol::All)
                                                .await
                                        }
                                        _ => unreachable!(),
                                    };
                                    if res.is_err() {
                                        error!("Failed to dial {:?}!", addr.to_string());
                                    }
                                }
                            }
                            Err(_) => {
                                error!("{:?} not a valid multiaddr", msg.payload());
                            }
                        }
                    }
                    _ => { // other channel
                    }
                }
            } else {
                warn!("Lost connection. Attempting reconnect...");
                let mut rconn_attempt: usize = 0;
                while let Err(err) = mqtt_client.reconnect().await {
                    rconn_attempt += 1;
                    info!("Error reconnecting #{}: {}", rconn_attempt, err);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                info!("Reconnected.");
            }
        }
        panic!("MQTT Context exited, Maybe service not ready...");
    });

    mqtt_tx.await?;
    service_tx.await?;

    Ok(())
}
