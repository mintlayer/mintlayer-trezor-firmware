// Copyright (c) 2021-2025 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-trezor-firmware/tree/mintlayer-master/core/embed/rust/src/mintlayer/deps/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]

// The purpose of this crate is to allow `mintlayer-core` to check that the version of
// `mintlayer-core-primitives` that it uses (and for which the encode-compatibility tests
// are run) is the same as the one used by the trezor firmware.

pub mod ml_primitives {
    pub use mintlayer_core_primitives::*;
}
