from typing import TYPE_CHECKING
from ubinascii import hexlify

from trezor import utils

if TYPE_CHECKING:
    from trezor.messages import MintlayerFirmwareInfo, MintlayerGetFirmwareInfo


MINTLAYER_FIRMWARE_VERSION_MAJOR = 1
MINTLAYER_FIRMWARE_VERSION_MINOR = 0
MINTLAYER_FIRMWARE_VERSION_PATCH = 0
MINTLAYER_FIRMWARE_PRERELEASE_ID = ""
# Note: 12-character hash should be more than enough for any forseable future
# (at the time of writing this, 9-character hashes seem to be sufficient, but it won't
# hurt to have some leeway).
MINTLAYER_FIRMWARE_BUILD_METADATA = hexlify(utils.SCM_REVISION).decode()[0:12]


async def get_firmware_info(_msg: MintlayerGetFirmwareInfo) -> MintlayerFirmwareInfo:
    from trezor.messages import MintlayerFirmwareInfo

    return MintlayerFirmwareInfo(
        major_version=MINTLAYER_FIRMWARE_VERSION_MAJOR,
        minor_version=MINTLAYER_FIRMWARE_VERSION_MINOR,
        patch_version=MINTLAYER_FIRMWARE_VERSION_PATCH,
        prerelease_id=MINTLAYER_FIRMWARE_PRERELEASE_ID,
        build_metadata=MINTLAYER_FIRMWARE_BUILD_METADATA,
    )
