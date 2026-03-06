"""
shard_manager.py
Author: Mourya Reddy Udumula
Role: Lead Architect & Cryptographic Engineer
Shard lifecycle management and node health monitoring for VaultZero.
Manages distributed shard placement across storage nodes, monitors node
availability, and coordinates reconstruction via shamir_handler.py
when nodes fail or become unreachable.
Part of the zero-trust architecture: no single node holds complete data
or the key required to reconstruct it.
"""

from __future__ import annotations
from typing import Dict, List, Optional


class ShardManager:
    """
    Manages shard placement across n_nodes storage nodes and enforces the
    threshold (k-of-n) availability constraint from Shamir Secret Sharing.

    This class handles the *orchestration* layer — deciding which node holds
    which shard, tracking node health, and deciding whether reconstruction is
    possible.  The actual cryptographic splitting and reconstruction are
    performed by ShamirVault (shamir_handler.py).

    Zero-trust guarantee: no single node holds enough information to reconstruct
    the secret; at least *threshold* nodes must be healthy simultaneously.

    IMPORTANT — In-Memory Simulation
    ---------------------------------
    This class manages shard state in **memory only**.  All shard data and
    node-health state are lost when the process exits or restarts.

    In production, shards must be persisted to the ``config.KEY_NODES`` paths
    via ``ShamirVault.distribute_key_async()``.  This in-memory implementation
    is intentionally provided for unit testing and algorithmic validation only.

    To bridge the gap to the persistence layer, call ``log_to_audit()`` with a
    ``DBHandler`` instance (from ``ops/audit_ledger.py``) after each state
    change.  When called without an argument (default ``None``), ``log_to_audit``
    prints a reminder that state is ephemeral.
    """

    def __init__(self, n_nodes: int = 3, threshold: int = 2) -> None:
        """
        Args:
            n_nodes:   Total number of storage nodes (default 3).
            threshold: Minimum nodes required for reconstruction (default 2).

        Raises:
            ValueError: If threshold > n_nodes or either value is < 1.
        """
        if n_nodes < 1:
            raise ValueError(f"n_nodes must be >= 1, got {n_nodes}")
        if threshold < 1 or threshold > n_nodes:
            raise ValueError(
                f"threshold must be between 1 and n_nodes ({n_nodes}), got {threshold}"
            )
        self.n_nodes   = n_nodes
        self.threshold = threshold
        # Internal state: node_id → {'status': 'healthy'|'failed', 'shard': bytes|None}
        self._nodes: Dict[int, dict] = {
            i: {'status': 'healthy', 'shard': None}
            for i in range(n_nodes)
        }

    # ------------------------------------------------------------------
    # Shard distribution
    # ------------------------------------------------------------------

    def distribute_shards(self, shards: list) -> Dict[int, object]:
        """
        Assign shards to node IDs in round-robin order.

        The number of shards should equal n_nodes (one per node), but this
        method handles mismatches gracefully by capping at min(len(shards), n_nodes).

        Args:
            shards: List of shard objects (bytes or tuples) produced by ShamirVault.

        Returns:
            {node_id: shard} mapping for all nodes that received a shard.
        """
        result: Dict[int, object] = {}
        for node_id, shard in zip(range(self.n_nodes), shards):
            self._nodes[node_id]['shard'] = shard
            result[node_id] = shard
        return result

    # ------------------------------------------------------------------
    # Node health management
    # ------------------------------------------------------------------

    def get_available_nodes(self) -> List[int]:
        """Return list of node IDs currently marked healthy."""
        return [
            nid for nid, info in self._nodes.items()
            if info['status'] == 'healthy'
        ]

    def mark_node_failed(self, node_id: int) -> None:
        """
        Mark *node_id* as unavailable (e.g., after a network timeout or disk failure).

        Args:
            node_id: Integer node identifier (0-indexed).

        Raises:
            KeyError: If node_id does not exist.
        """
        if node_id not in self._nodes:
            raise KeyError(f"Node {node_id} does not exist (n_nodes={self.n_nodes})")
        self._nodes[node_id]['status'] = 'failed'

    def mark_node_healthy(self, node_id: int) -> None:
        """Mark a previously failed node as healthy again (e.g., after recovery)."""
        if node_id not in self._nodes:
            raise KeyError(f"Node {node_id} does not exist (n_nodes={self.n_nodes})")
        self._nodes[node_id]['status'] = 'healthy'

    # ------------------------------------------------------------------
    # Reconstruction helpers
    # ------------------------------------------------------------------

    def recover_shards(self, available_nodes: Optional[List[int]] = None) -> list:
        """
        Return shards from the specified (or all available) nodes for reconstruction.

        Args:
            available_nodes: Optional explicit list of node IDs to recover from.
                             Defaults to all currently healthy nodes.

        Returns:
            List of shards held by the specified nodes (None entries excluded).
        """
        nodes = available_nodes if available_nodes is not None else self.get_available_nodes()
        return [
            self._nodes[nid]['shard']
            for nid in nodes
            if nid in self._nodes and self._nodes[nid]['shard'] is not None
        ]

    def can_reconstruct(self) -> bool:
        """
        Return True if at least *threshold* healthy nodes are available.

        This is a fast pre-flight check before attempting actual reconstruction
        via ShamirVault to avoid unnecessary I/O on under-provisioned clusters.
        """
        return len(self.get_available_nodes()) >= self.threshold

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def node_health_report(self) -> Dict[int, str]:
        """
        Return a health snapshot for all nodes.

        Returns:
            {node_id: 'healthy' | 'failed'} for every node.
        """
        return {nid: info['status'] for nid, info in self._nodes.items()}

    def log_to_audit(self, audit_ledger=None) -> None:
        """
        Optional persistence hook — forwards the current shard health snapshot
        to an audit ledger for tamper-evident forensic logging.

        This method is a **no-op** when *audit_ledger* is ``None`` (the default),
        which is the expected behaviour in unit-test and in-memory demo mode.
        Pass a ``DBHandler`` instance (from ``ops/audit_ledger.py``) for
        production use.

        IMPORTANT: ShardManager itself is in-memory only.  This hook is the
        recommended bridge to the persistence layer — do NOT add direct file I/O
        to this class.

        Args:
            audit_ledger: Optional ``DBHandler`` instance.  If ``None``, prints
                          a reminder that state is in-memory only and will be
                          lost on process exit.

        Returns:
            None
        """
        if audit_ledger is None:
            print(
                "[ShardManager] IN-MEMORY MODE: shard state is not persisted. "
                "Pass a DBHandler instance to log_to_audit() for persistence."
            )
            return
        # Delegate to audit_ledger.log_event for each node in the health report.
        for node_id, status in self.node_health_report().items():
            audit_ledger.log_event(
                action=f"node_{node_id}_{status}",
                filename=f"shard_{node_id}",
                user="ShardManager",
            )

    def __repr__(self) -> str:
        healthy = len(self.get_available_nodes())
        return (
            f"ShardManager(n_nodes={self.n_nodes}, threshold={self.threshold}, "
            f"healthy={healthy}/{self.n_nodes})"
        )


if __name__ == '__main__':
    from Crypto.Protocol.SecretSharing import Shamir

    print("=== ShardManager Demo ===\n")
    manager = ShardManager(n_nodes=3, threshold=2)

    # Simulate splitting a 16-byte secret
    secret = b"SuperSecretKey!!"
    shares = Shamir.split(2, 3, secret)
    print(f"Secret : {secret}")
    print(f"Shares : {[(idx, data[:4].hex()+'...') for idx, data in shares]}\n")

    manager.distribute_shards(shares)
    print(f"Health after distribution : {manager.node_health_report()}")
    print(f"Can reconstruct?          : {manager.can_reconstruct()}")

    # Simulate node 1 failure
    manager.mark_node_failed(1)
    print(f"\nAfter node 1 failure:")
    print(f"  Health report  : {manager.node_health_report()}")
    print(f"  Can reconstruct: {manager.can_reconstruct()}")

    # Recover and reconstruct
    recovered = manager.recover_shards()
    reconstructed = Shamir.combine(recovered)
    print(f"\nReconstructed secret: {reconstructed}")
    print(f"Match: {reconstructed == secret}")

    # Demonstrate in-memory disclaimer via log_to_audit(None)
    print()
    manager.log_to_audit(None)
