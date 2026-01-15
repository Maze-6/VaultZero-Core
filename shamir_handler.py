import os
import asyncio
import aiofiles
from binascii import hexlify, unhexlify
from Crypto.Protocol.SecretSharing import Shamir
from typing import List
import config

class ShamirVault:
    @staticmethod
    async def async_write_shard(path: str, data: bytes) -> None:
        """Async write with 10ms simulated latency."""
        await asyncio.sleep(0.01) 
        async with aiofiles.open(path, "w") as f:
            await f.write(hexlify(data).decode('utf-8'))

    @staticmethod
    def distribute_key_async(secret_key: str, filename: str, active_nodes: List[bool]) -> bool:
        """Splits master key into shards and distributes to key_storage nodes."""
        try:
            key_bytes: bytes = secret_key.encode('utf-8')
            padded_key: bytes = key_bytes.ljust(16, b' ')
            shares = Shamir.split(2, 3, padded_key)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            tasks = []
            for idx, share_data in shares:
                if active_nodes[idx-1]:
                    path = os.path.join(config.KEY_NODES[idx-1], f"{filename}.key.{idx-1}")
                    tasks.append(ShamirVault.async_write_shard(path, share_data))
            
            if tasks:
                loop.run_until_complete(asyncio.gather(*tasks))
            loop.close()
            return True
        except Exception as e: 
            raise ValueError(f"Sharding Error: {str(e)}")

    @staticmethod
    def reconstruct_key(filename: str, active_nodes: List[bool]) -> str:
        """Reconstructs key and identifies missing shards across the grid."""
        shares = []
        missing_shards = []
        node_names = ["Alpha", "Beta", "Gamma"]

        for i in range(3):
            path = os.path.join(config.KEY_NODES[i], f"{filename}.key.{i}")
            
            # Check if file exists physically on disk
            if not os.path.exists(path):
                missing_shards.append(node_names[i])
                continue

            # Only add to reconstruction if node is logically ONLINE in dashboard
            if active_nodes[i]:
                with open(path, "r") as f:
                    shares.append((i + 1, unhexlify(f.read().strip())))
        
        # If any shards are physically missing, notify the user immediately
        if missing_shards:
            raise FileNotFoundError(f"Missing Shards Detected: Node(s) {', '.join(missing_shards)}")

        if len(shares) < 2: 
            raise ValueError(f"QUORUM FAILURE: Only {len(shares)} nodes online. Need 2.")
        
        try:
            return Shamir.combine(shares).strip().decode('utf-8')
        except Exception as e:
            raise ValueError(f"Reconstruction Error: {str(e)}")