use async_nats::jetstream;
use tokio_stream::StreamExt;

use super::EventSource;

/// NATS JetStream consumer that yields events as JSON strings.
pub struct NatsSource {
    messages: jetstream::consumer::pull::Stream,
}

impl NatsSource {
    /// Connect to NATS and subscribe to a JetStream stream via pull consumer.
    ///
    /// `url` is the NATS server URL (e.g. "nats://localhost:4222").
    /// `subject` is the subject filter (e.g. "hel.events.>").
    pub async fn connect(url: &str, subject: &str) -> Result<Self, async_nats::Error> {
        let client = async_nats::connect(url).await?;
        let jetstream = jetstream::new(client);

        let stream = jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: "rsigma-events".to_string(),
                subjects: vec![subject.to_string()],
                ..Default::default()
            })
            .await?;

        let consumer = stream
            .get_or_create_consumer(
                "rsigma-daemon",
                jetstream::consumer::pull::Config {
                    durable_name: Some("rsigma-daemon".to_string()),
                    filter_subject: subject.to_string(),
                    ..Default::default()
                },
            )
            .await?;

        let messages = consumer.messages().await?;

        Ok(NatsSource { messages })
    }
}

impl EventSource for NatsSource {
    async fn recv(&mut self) -> Option<String> {
        loop {
            match self.messages.next().await {
                Some(Ok(msg)) => {
                    let payload = String::from_utf8_lossy(&msg.payload).to_string();
                    if let Err(e) = msg.ack().await {
                        tracing::warn!(error = %e, "Failed to ack NATS message");
                    }
                    if !payload.trim().is_empty() {
                        return Some(payload);
                    }
                }
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "NATS message error");
                    continue;
                }
                None => return None,
            }
        }
    }
}
