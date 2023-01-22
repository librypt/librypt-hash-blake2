#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

mod blake2b;
mod blake2s;

pub use blake2b::Blake2b;
pub use blake2s::Blake2s;
