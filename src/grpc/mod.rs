//! gRPC service for token verification and permission checking.

pub mod auth_service;

pub mod proto {
    tonic::include_proto!("signet.auth.v1");
}

pub use auth_service::AuthServiceImpl;
