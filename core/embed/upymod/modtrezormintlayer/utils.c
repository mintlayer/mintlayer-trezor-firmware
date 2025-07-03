#include "py/runtime.h"

#include "utils.h"

void handle_err(ByteArray *res) {
  if (res->data != NULL) {
    return;
  }

  switch (res->len_or_err.err) {
    case WrongHashSize:
      mp_raise_ValueError("Invalid hash size");
      break;
    case InvalidUtxoType:
      mp_raise_ValueError("Invalid UTXO type");
      break;
    case InvalidAmount:
      mp_raise_ValueError("Invalid amount");
      break;
    case InvalidAccountCommand:
      mp_raise_ValueError("Invalid account command");
      break;
    case InvalidDestination:
      mp_raise_ValueError("Invalid destination");
      break;
    case InvalidIsTokenUnfreezable:
      mp_raise_ValueError("Invalid token unfreezable flag");
      break;
    case InvalidIsTokenFreezable:
      mp_raise_ValueError("Invalid token freezable flag");
      break;
    case InvalidVrfPublicKey:
      mp_raise_ValueError("Invalid VRF public key");
      break;
    case InvalidPublicKey:
      mp_raise_ValueError("Invalid public key");
      break;
    case InvalidOutputTimeLock:
      mp_raise_ValueError("Invalid output time lock");
      break;
    case InvalidTokenTotalSupply:
      mp_raise_ValueError("Invalid token total supply");
      break;
    default:
      mp_raise_ValueError("Unknown error");
      break;
  }
}
