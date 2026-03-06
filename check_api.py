import inspect
from crypto_engine import CryptoEngine
from shamir_handler import ShamirVault

print("=== CryptoEngine.__init__ ===")
print(inspect.signature(CryptoEngine.__init__))

print("\n=== CryptoEngine.encrypt_data ===")
print(inspect.signature(CryptoEngine.encrypt_data))

print("\n=== CryptoEngine.decrypt_payload ===")
print(inspect.signature(CryptoEngine.decrypt_payload))

print("\n=== ShamirVault.distribute_key_async ===")
print(inspect.signature(ShamirVault.distribute_key_async))

print("\n=== ShamirVault.reconstruct_key ===")
print(inspect.signature(ShamirVault.reconstruct_key))

print("\n=== reconstruct_key return type test ===")
import os, config

# Write a test shard to check return type
os.makedirs(list(config.KEY_NODES.values())[0], exist_ok=True)
ShamirVault.distribute_key_async("mypassword123", "__api_test__", [True, True, True])
result = ShamirVault.reconstruct_key("__api_test__", [True, True, True])
print(f"Type returned: {type(result)}")
print(f"Raw value repr: {repr(result)}")
print(f"Stripped: {repr(result.strip()) if isinstance(result, str) else repr(result.strip())}")

# Cleanup
for i in range(3):
    kp = os.path.join(list(config.KEY_NODES.values())[i], "__api_test__.key." + str(i))
    if os.path.exists(kp): os.remove(kp)
