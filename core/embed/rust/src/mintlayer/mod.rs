use crate::micropython::ffi;
use core::{
    alloc::{GlobalAlloc, Layout},
    num::ParseIntError,
    ptr::null_mut,
    str::{from_utf8, FromStr},
};

use parity_scale_codec::{Decode, DecodeAll, Encode};

const TEN: UnsignedIntType = 10;

#[no_mangle]
extern "C" fn mintlayer_screen_fatal_error_rust(
    title: *const cty::c_char,
    msg: *const cty::c_char,
    footer: *const cty::c_char,
) -> u32 {
    42
}

#[repr(C)]
pub struct ByteArray {
    data: *const cty::c_uchar,
    len: cty::c_uint,
}

#[no_mangle]
extern "C" fn mintlayer_encode_utxo_input(data: *const u8, data_len: u32, index: u32) -> ByteArray {
    let tx_hash = unsafe { core::slice::from_raw_parts(data, data_len as usize) };
    let utxo_outpoint = UtxoOutPoint::new(
        OutPointSourceId::Transaction(H256(tx_hash.try_into().expect("foo"))),
        index,
    );
    let tx_input = TxInput::Utxo(utxo_outpoint);
    let vec_data = tx_input.encode();
    // Extracting the raw pointer and length from the Vec<u8>
    let ptr_data = vec_data.as_ptr();
    let len = vec_data.len() as cty::c_uint;

    // Prevent Rust from freeing the memory associated with vec_data
    core::mem::forget(vec_data);

    // Construct and return the ByteArray struct
    ByteArray {
        data: ptr_data,
        len,
    }
}

#[no_mangle]
extern "C" fn mintlayer_encode_transfer_output(
    amount_data: *const u8,
    amount_data_len: u32,
    destination_data: *const u8,
    destination_data_len: u32,
) -> ByteArray {
    let coin_amount = unsafe { core::slice::from_raw_parts(amount_data, amount_data_len as usize) };
    let coin_amount = from_utf8(coin_amount);
    let bytes = [
        2, 0, 3, 191, 111, 141, 82, 218, 222, 119, 249, 94, 156, 108, 148, 136, 253, 132, 146, 169,
        156, 9, 255, 35, 9, 92, 175, 251, 46, 100, 9, 209, 116, 106, 222,
    ];
    Destination::decode_all(&mut bytes.as_ref()).expect("ok");

    let mut destination_bytes =
        unsafe { core::slice::from_raw_parts(destination_data, destination_data_len as usize) };
    let destination = Destination::decode_all(&mut destination_bytes.as_ref()).expect("ok");

    // match &destination {
    //     Destination::AnyoneCanSpend => println!("anyone can spend dest"),
    //     Destination::PublicKey(_) => println!("pk dest"),
    //     Destination::PublicKeyHash(_) => println!("pkh dest"),
    // };

    let txo = TxOutput::Transfer(
        // OutputValue::Coin(
        //     Amount::from_fixedpoint_str(coin_amount.expect("fixme"), 11).expect("fixme"),
        // ),
        OutputValue::Coin(Amount::from_atoms(1)),
        destination,
    );

    let vec_data = txo.encode();
    // Extracting the raw pointer and length from the Vec<u8>
    let ptr_data = vec_data.as_ptr();
    let len = vec_data.len() as cty::c_uint;

    // Prevent Rust from freeing the memory associated with vec_data
    core::mem::forget(vec_data);

    // Construct and return the ByteArray struct
    ByteArray {
        data: ptr_data,
        len,
    }
}

#[derive(Encode, Debug, PartialEq, Eq)]
struct CompactLength {
    #[codec(compact)]
    pub value: u32,
}

#[no_mangle]
extern "C" fn mintlayer_encode_compact_length(length: u32) -> ByteArray {
    let vec_data = CompactLength { value: length }.encode();
    // Extracting the raw pointer and length from the Vec<u8>
    let ptr_data = vec_data.as_ptr();
    let len = vec_data.len() as cty::c_uint;

    // Prevent Rust from freeing the memory associated with vec_data
    core::mem::forget(vec_data);

    // Construct and return the ByteArray struct
    ByteArray {
        data: ptr_data,
        len,
    }
}

struct CustomAllocator;

unsafe impl GlobalAlloc for CustomAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr_void = ffi::gc_alloc(layout.size(), 0); // Call ffi::gc_alloc
            if ptr_void.is_null() {
                return null_mut();
            }
            ptr_void as *mut u8 // Cast the pointer to *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Implement deallocation logic here if needed
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CustomAllocator = CustomAllocator;

/// Specifies which parts of the transaction a signature commits to.
///
/// The values of the flags are the same as in Bitcoin.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Ord, PartialOrd, Encode, Decode)]
pub struct SigHashType(u8);

impl SigHashType {
    pub const ALL: u8 = 0x01;
    pub const NONE: u8 = 0x02;
    pub const SINGLE: u8 = 0x03;
    pub const ANYONECANPAY: u8 = 0x80;

    const MASK_OUT: u8 = 0x7f;
    const MASK_IN: u8 = 0x80;

    // pub fn inputs_mode(&self) -> InputsMode {
    //     match self.0 & Self::MASK_IN {
    //         Self::ANYONECANPAY => InputsMode::AnyoneCanPay,
    //         _ => InputsMode::CommitWhoPays,
    //     }
    // }

    // pub fn outputs_mode(&self) -> OutputsMode {
    //     match self.0 & Self::MASK_OUT {
    //         Self::NONE => OutputsMode::None,
    //         Self::SINGLE => OutputsMode::Single,
    //         _ => OutputsMode::All,
    //     }
    // }

    pub fn get(&self) -> u8 {
        self.0
    }
}

type UnsignedIntType = u128;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct Amount {
    #[codec(compact)]
    atoms: UnsignedIntType,
}

impl Amount {
    pub const MAX: Self = Self::from_atoms(UnsignedIntType::MAX);
    pub const ZERO: Self = Self::from_atoms(0);

    pub const fn from_atoms(v: UnsignedIntType) -> Self {
        Amount { atoms: v }
    }

    pub const fn into_atoms(&self) -> UnsignedIntType {
        self.atoms
    }

    pub fn from_fixedpoint_str(amount_str: &str, decimals: u8) -> Option<Self> {
        amount_str
            .parse::<DecimalAmount>()
            .ok()?
            .to_amount(decimals)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DecimalAmount {
    mantissa: UnsignedIntType,
    decimals: u8,
}

impl DecimalAmount {
    pub const ZERO: Self = Self::from_uint_integral(0);

    /// Convert from integer with no decimals
    pub const fn from_uint_integral(number: u128) -> Self {
        Self::from_uint_decimal(number, 0)
    }

    /// Convert from integer, interpreting the last N digits as the fractional
    /// part
    pub const fn from_uint_decimal(mantissa: UnsignedIntType, decimals: u8) -> Self {
        Self { mantissa, decimals }
    }

    /// Convert from amount, keeping all decimal digits
    pub const fn from_amount_full_padding(amount: Amount, decimals: u8) -> Self {
        Self::from_uint_decimal(amount.into_atoms(), decimals)
    }

    /// Convert from amount, keeping as few decimal digits as possible (without
    /// losing precision)
    pub const fn from_amount_no_padding(amount: Amount, decimals: u8) -> Self {
        Self::from_amount_full_padding(amount, decimals).without_padding()
    }

    /// Convert to amount using given number of decimals
    pub fn to_amount(self, decimals: u8) -> Option<Amount> {
        Some(Amount::from_atoms(self.with_decimals(decimals)?.mantissa))
    }

    /// Change the number of decimals. Can only increase decimals, otherwise we
    /// risk losing digits.
    pub fn with_decimals(self, decimals: u8) -> Option<Self> {
        let extra_decimals = decimals.checked_sub(self.decimals)?;
        let mantissa = self
            .mantissa
            .checked_mul(TEN.checked_pow(extra_decimals as u32)?)?;
        Some(Self::from_uint_decimal(mantissa, decimals))
    }

    /// Trim trailing zeroes in the fractional part
    pub const fn without_padding(mut self) -> Self {
        while self.decimals > 0 && self.mantissa % TEN == 0 {
            self.mantissa /= TEN;
            self.decimals -= 1;
        }
        self
    }

    /// Check this is the same number presented with the same precision
    pub fn is_same(&self, other: &Self) -> bool {
        (self.mantissa, self.decimals) == (other.mantissa, other.decimals)
    }
}

fn empty_to_zero(s: &str) -> &str {
    match s {
        "" => "0",
        s => s,
    }
}

#[derive(/* thiserror::Error, */ Debug, PartialEq, Eq)]
pub enum ParseError {
    // #[error("Resulting number is too big")]
    OutOfRange,

    // #[error("The number string is too long")]
    StringTooLong,

    // #[error("Empty input")]
    EmptyString,

    // #[error("Invalid character used in number")]
    IllegalChar,

    // #[error("Number does not contain any digits")]
    NoDigits,
    // #[error(transparent)]
    IntParse(ParseIntError),
}

impl FromStr for DecimalAmount {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // ensure!(s.len() <= 100, ParseError::StringTooLong);

        let s = s.trim_matches(' ');
        let s = s.replace('_', "");
        // ensure!(!s.is_empty(), ParseError::EmptyString);

        let (int_str, frac_str) = s.split_once('.').unwrap_or((&s, ""));

        let mut chars = int_str.chars().chain(frac_str.chars());
        // ensure!(chars.all(|c| c.is_ascii_digit()), ParseError::IllegalChar);
        // ensure!(int_str.len() + frac_str.len() > 0, ParseError::NoDigits);

        let int: UnsignedIntType = empty_to_zero(int_str)
            .parse()
            .map_err(ParseError::IntParse)?;
        let frac: UnsignedIntType = empty_to_zero(frac_str)
            .parse()
            .map_err(ParseError::IntParse)?;

        let decimals: u8 = frac_str
            .len()
            .try_into()
            .expect("Checked string length above");

        let mantissa = TEN
            .checked_pow(decimals as u32)
            .and_then(|mul| int.checked_mul(mul))
            .and_then(|shifted| shifted.checked_add(frac))
            .ok_or(ParseError::OutOfRange)?;

        Ok(Self::from_uint_decimal(mantissa, decimals))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OutputValue {
    Coin(Amount),
    // TokenV0(Box<TokenData>),
    // TokenV1(TokenId, Amount),
}

const HASH_SIZE: usize = 20;
const PK_SIZE: usize = 33;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct PublicKeyHash(pub [u8; HASH_SIZE]);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct PublicKey(pub [u8; PK_SIZE]);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub enum PublicKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(PublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    #[codec(index = 0)]
    AnyoneCanSpend, /* zero verification; used primarily for testing. Never use this for real
                     * money */
    #[codec(index = 1)]
    PublicKeyHash(PublicKeyHash),
    #[codec(index = 2)]
    PublicKey(PublicKeyHolder),
    // #[codec(index = 3)]
    // ScriptHash(Id<Script>),
    // #[codec(index = 4)]
    // ClassicMultisig(PublicKeyHash),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum TxOutput {
    /// Transfer an output, giving the provided Destination the authority to
    /// spend it (no conditions)
    #[codec(index = 0)]
    Transfer(OutputValue, Destination),
    // /// Same as Transfer, but with the condition that an output can only be
    // /// specified after some point in time.
    //     #[codec(index = 1)]
    //     LockThenTransfer(OutputValue, Destination, OutputTimeLock),
    //     /// Burn an amount (whether coin or token)
    //     #[codec(index = 2)]
    //     Burn(OutputValue),
    //     /// Output type that is used to create a stake pool
    //     #[codec(index = 3)]
    //     CreateStakePool(PoolId, Box<StakePoolData>),
    //     /// Output type that represents spending of a stake pool output in a
    // block     /// reward in order to produce a block
    //     #[codec(index = 4)]
    //     ProduceBlockFromStake(Destination, PoolId),
    //     /// Create a delegation; takes the owner destination (address authorized
    // to     /// withdraw from the delegation) and a pool id
    //     #[codec(index = 5)]
    //     CreateDelegationId(Destination, PoolId),
    //     /// Transfer an amount to a delegation that was previously created for
    //     /// staking
    //     #[codec(index = 6)]
    //     DelegateStaking(Amount, DelegationId),
    //     #[codec(index = 7)]
    //     IssueFungibleToken(Box<TokenIssuance>),
    //     #[codec(index = 8)]
    //     IssueNft(TokenId, Box<NftIssuance>, Destination),
    //     #[codec(index = 9)]
    //     DataDeposit(Vec<u8>),
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Encode, Decode)]
pub struct H256(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Ord, PartialOrd)]
pub enum OutPointSourceId {
    #[codec(index = 0)]
    Transaction(H256),
    #[codec(index = 1)]
    BlockReward(H256),
}

impl OutPointSourceId {
    pub fn get_tx_id(&self) -> Option<&H256> {
        match self {
            OutPointSourceId::Transaction(id) => Some(id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, Ord, PartialOrd)]
pub struct UtxoOutPoint {
    id: OutPointSourceId,
    index: u32,
}

impl UtxoOutPoint {
    pub fn new(outpoint_source_id: OutPointSourceId, output_index: u32) -> Self {
        UtxoOutPoint {
            id: outpoint_source_id,
            index: output_index,
        }
    }

    pub fn source_id(&self) -> OutPointSourceId {
        self.id.clone()
    }

    pub fn output_index(&self) -> u32 {
        self.index
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum TxInput {
    #[codec(index = 0)]
    Utxo(UtxoOutPoint),
    // // TODO: after the fork AccountOutPoint can be replaced with (AccountNonce,
    // AccountSpending) #[codec(index = 1)]
    // Account(AccountOutPoint),
    // #[codec(index = 2)]
    // AccountCommand(AccountNonce, AccountCommand),
}

// fn signature_hash(
//     mode: SigHashType,
//     tx: &Transaction,
//     inputs_utxos: &[Option<&TxOutput>],
//     input_num: usize,
// ) -> Result<H256, DestinationSigError> {
//     let mut stream = DefaultHashAlgoStream::new();

//     stream_signature_hash(tx, inputs_utxos, &mut stream, mode, input_num)?;

//     let result = stream.finalize().into();
//     Ok(result)
// }
