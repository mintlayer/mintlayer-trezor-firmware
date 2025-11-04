#![no_std]

// The purpose of this crate is to allow `mintlayer-core` to check that the version of
// `mintlayer-core-primitives` that it uses (and for which the encode-compatibility tests
// are run) is the same as the one used by the trezor firmware.

pub mod ml_primitives {
    pub use mintlayer_core_primitives::*;
}
