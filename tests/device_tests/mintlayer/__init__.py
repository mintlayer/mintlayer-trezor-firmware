import pytest

# Marks common to all Mintlayer tests (must be imported explicitly in each test file)
pytestmark = [
    pytest.mark.altcoin,
    pytest.mark.mintlayer,
    pytest.mark.setup_client(
        mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ),
    # This means that the tests should be run on all models except for the legacy one (i.e. Model One).
    pytest.mark.models("core"),
]
