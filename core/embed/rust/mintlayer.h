#include "common.h"

uint32_t mintlayer_screen_fatal_error_rust(const char* title, const char* msg,
                                           const char* footer);

typedef enum {
  WrongHashSize = 1,
  InvalidUtxoType = 2,
  InvalidAmount = 3,
  InvalidAccountCommand = 4,
  InvalidDestination = 5,
  InvalidIsTokenUnfreezable = 6,
  InvalidIsTokenFreezable = 7,
  InvalidVrfPublicKey = 8,
  InvalidPublicKey = 9,
  InvalidOutputTimeLock = 10,
  InvalidTokenTotalSupply = 11,
} MintlayerErrorCode;

typedef union {
  uint32_t len;
  MintlayerErrorCode err;
} LenOrError;

typedef struct {
  const uint8_t* data;
  LenOrError len_or_err;
} ByteArray;

ByteArray mintlayer_encode_utxo_input(const unsigned char* hex,
                                      uint32_t hex_len, uint32_t index,
                                      uint32_t utxo_type);

ByteArray mintlayer_encode_account_spending_input(
    uint64_t nonce, const unsigned char* delegation_id_data,
    uint32_t delegation_id_data_len, const unsigned char* amount_data,
    uint32_t amount_data_len);

ByteArray mintlayer_encode_token_account_command_input(
    uint64_t nonce, uint32_t command, const unsigned char* token_id_data,
    uint32_t token_id_data_len, const unsigned char* data, uint32_t data_len);

ByteArray mintlayer_encode_conclude_order_account_command_input(
    uint64_t nonce, const unsigned char* order_id_data,
    uint32_t order_id_data_len);

ByteArray mintlayer_encode_fill_order_account_command_input(
    uint64_t nonce, const unsigned char* order_id_data,
    uint32_t order_id_data_len, const unsigned char* coin_amount_data,
    uint32_t coin_amount_data_len, const unsigned char* destination_data,
    uint32_t destination_data_len);

ByteArray mintlayer_encode_transfer_output(
    const unsigned char* coin_amount_data, uint32_t coin_amount_data_len,
    const unsigned char* token_id_data, uint32_t token_id_data_len,
    const unsigned char* address_data, uint32_t address_data_len);

ByteArray mintlayer_encode_lock_then_transfer_output(
    const unsigned char* coin_amount_data, uint32_t coin_amount_data_len,
    const unsigned char* token_id_data, uint32_t token_id_data_len,
    uint8_t lock_type, uint64_t lock_amount, const unsigned char* address_data,
    uint32_t address_data_len);

ByteArray mintlayer_encode_burn_output(const unsigned char* coin_amount_data,
                                       uint32_t coin_amount_data_len,
                                       const unsigned char* token_id_data,
                                       uint32_t token_id_data_len);

ByteArray mintlayer_encode_create_stake_pool_output(
    const unsigned char* pool_id_data, uint32_t pool_id_data_len,
    const unsigned char* pledge_amount_data, uint32_t pledge_amount_data_len,
    const unsigned char* staker_destination_data,
    uint32_t staker_destination_data_len,
    const unsigned char* vrf_public_key_data, uint32_t vrf_public_key_data_len,
    const unsigned char* decommission_destination_data,
    uint32_t decommission_destination_data_len,
    uint16_t margin_ratio_per_thousand,
    const unsigned char* cost_per_block_amount_data,
    uint32_t cost_per_block_amount_data_len);

ByteArray mintlayer_encode_produce_from_stake_output(
    const unsigned char* destination_data, uint32_t destination_data_len,
    const unsigned char* pool_id_data, uint32_t pool_id_data_len);

ByteArray mintlayer_encode_create_delegation_id_output(
    const unsigned char* destination_data, uint32_t destination_data_len,
    const unsigned char* pool_id_data, uint32_t pool_id_data_len);

ByteArray mintlayer_encode_delegate_staking_output(
    const unsigned char* amount_data, uint32_t amount_data_len,
    const unsigned char* pool_id_data, uint32_t pool_id_data_len);

ByteArray mintlayer_encode_issue_fungible_token_output(
    const unsigned char* token_ticker_data, uint32_t token_ticker_data_len,
    uint8_t number_of_decimals, const unsigned char* metadata_uri_data,
    uint32_t metadata_uri_data_len, uint32_t total_supply_type,
    const unsigned char* fixed_amount_data, uint32_t fixed_amount_data_len,
    const unsigned char* authority_data, uint32_t authority_data_len,
    uint8_t is_freezable);

ByteArray mintlayer_encode_issue_nft_output(
    const unsigned char* token_id_data, uint32_t token_id_data_len,
    const unsigned char* creator_data, uint32_t creator_data_len,
    const unsigned char* name_data, uint32_t name_data_len,
    const unsigned char* description_data, uint32_t description_data_len,
    const unsigned char* ticker_data, uint32_t ticker_data_len,
    const unsigned char* icon_uri_data, uint32_t icon_uri_data_len,
    const unsigned char* additional_metadata_uri_data,
    uint32_t additional_metadata_uri_data_len,
    const unsigned char* media_uri_data, uint32_t media_uri_data_len,
    const unsigned char* media_hash_data, uint32_t media_hash_data_len,
    const unsigned char* destination_data, uint32_t destination_data_len);

ByteArray mintlayer_encode_data_deposit_output(
    const unsigned char* deposit_data, uint32_t deposit_data_len);

ByteArray mintlayer_encode_htlc_output(
    const unsigned char* coin_amount_data, uint32_t coin_amount_data_len,
    const unsigned char* token_id_data, uint32_t token_id_data_len,
    uint8_t lock_type, uint64_t lock_amount,
    const unsigned char* refund_key_data, uint32_t refund_key_data_len,
    const unsigned char* spend_key_data, uint32_t spend_key_data_len,
    const unsigned char* secret_hash_data, uint32_t secret_hash_data_len);

ByteArray mintlayer_encode_anyone_can_take_output(
    const unsigned char* conclude_key_data, uint32_t conclude_key_data_len,
    const unsigned char* ask_coin_amount_data,
    uint32_t ask_coin_amount_data_len, const unsigned char* ask_token_id_data,
    uint32_t ask_token_id_data_len, const unsigned char* give_coin_amount_data,
    uint32_t give_coin_amount_data_len, const unsigned char* give_token_id_data,
    uint32_t give_token_id_data_len);

ByteArray mintlayer_encode_compact_length(uint32_t length);
