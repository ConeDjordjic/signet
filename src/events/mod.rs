//! Event-driven architecture with outbox pattern.

pub mod outbox;
pub mod publisher;
pub mod types;

pub use outbox::OutboxService;
pub use publisher::{EventPublisher, EventPublisherBuilder};
pub use types::*;
