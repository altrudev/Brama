from __future__ import annotations

import hashlib
import re

SHA256 = re.compile(r"^[a-f0-9]{64}$")


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(digests: list[str]) -> str:
    if not digests:
        raise ValueError("at least one digest required")
    if any(not SHA256.fullmatch(value) for value in digests):
        raise ValueError("all values must be SHA-256 digests")
    layer = list(digests)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [_hash_pair(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def merkle_proof(digests: list[str], index: int) -> list[tuple[str, str]]:
    merkle_root(digests)
    if index < 0 or index >= len(digests):
        raise IndexError("index out of range")
    layer = list(digests)
    position = index
    proof: list[tuple[str, str]] = []
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        sibling = position - 1 if position % 2 else position + 1
        side = "left" if sibling < position else "right"
        proof.append((side, layer[sibling]))
        layer = [_hash_pair(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        position //= 2
    return proof


def verify_merkle_proof(digest: str, proof: list[tuple[str, str]], expected_root: str) -> bool:
    if not SHA256.fullmatch(digest) or not SHA256.fullmatch(expected_root):
        return False
    current = digest
    for side, sibling in proof:
        if not SHA256.fullmatch(sibling) or side not in {"left", "right"}:
            return False
        current = _hash_pair(sibling, current) if side == "left" else _hash_pair(current, sibling)
    return current == expected_root
