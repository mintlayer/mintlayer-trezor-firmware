#include "py/runtime.h"

#include "utils.h"

void handle_err(ByteArray *res) {
  if (res->data != NULL) {
    return;
  }

  switch (res->len_or_err.err) {
    case WrongHashSize:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid hash size"));
      break;
    case InvalidUtxoType:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid UTXO type"));
      break;
    case InvalidAmount:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid amount"));
      break;
    case InvalidAccountCommand:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid account command"));
      break;
    case InvalidDestination:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid destination"));
      break;
    case InvalidIsTokenUnfreezable:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid token unfreezable flag"));
      break;
    case InvalidIsTokenFreezable:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid token freezable flag"));
      break;
    case InvalidVrfPublicKey:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid VRF public key"));
      break;
    case PublicKeyDestinationExpected:
      mp_raise_ValueError(MP_ERROR_TEXT("Public key destination expected"));
      break;
    case InvalidOutputTimeLock:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid output time lock"));
      break;
    case InvalidTokenTotalSupply:
      mp_raise_ValueError(MP_ERROR_TEXT("Invalid token total supply"));
      break;
    default:
      mp_raise_ValueError(MP_ERROR_TEXT("Unknown error"));
      break;
  }
}
