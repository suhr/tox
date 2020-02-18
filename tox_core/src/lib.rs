/*!
Rust implementation of the [Tox protocol](https://zetok.github.io/tox-spec).

Repo: https://github.com/tox-rs/tox

*/

#![forbid(unsafe_code)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/tox-rs/logo/master/logo.png")]
// Remove it when it will be fixed in nom parser
#![allow(clippy::redundant_closure)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate cookie_factory;

#[macro_use]
mod error;
#[macro_use]
pub mod binary_io;
pub mod io_tokio;
pub mod ip_port;
pub mod packed_node;
pub mod crypto_core;
pub mod time;
pub mod state_format;
pub mod toxid;
pub mod tcp;
pub mod dht;
pub mod onion;
pub mod net_crypto;
pub mod utils;
pub mod friend_connection;
pub mod messenger;
pub mod stats;
