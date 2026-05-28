# Copyright 2026 Rick Harold
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

import os
from pathlib import Path

import pytest

import qduck
from qduck.exceptions import DecryptionError
from qduck.file_format import CHUNK_FINAL_BIT, CHUNK_LEN_FLAG_SIZE, CHUNK_LEN_MASK, MIN_CHUNK_SIZE

AAD = b"test aad"


def _encrypt_sample(tmp_path: Path, data: bytes | None = None, chunk_size: int = MIN_CHUNK_SIZE):
    if data is None:
        # More than two chunks so truncation/reorder tests are meaningful.
        data = (b"qduck-corruption-test-" * 700)
    src = tmp_path / "plain.bin"
    enc = tmp_path / "plain.qduck"
    src.write_bytes(data)
    aes_key = os.urandom(32)
    qduck.encrypt_file(str(src), str(enc), aes_key, aad=AAD, chunk_size=chunk_size)
    return src, enc, aes_key, data


def _decrypt(enc: Path, out: Path, aes_key: bytes, aad: bytes | None = AAD):
    qduck.decrypt_file(str(enc), str(out), aes_key, aad=aad)


def _header_len(blob: bytes) -> int:
    # v3 header: magic(8), version(1), flags(1), header_len(2)
    return int.from_bytes(blob[10:12], "big")


def _chunk_records(blob: bytes):
    """Return (start, end, payload_start, payload_end, is_final) for each chunk."""
    pos = _header_len(blob)
    records = []
    while pos < len(blob):
        prefix_start = pos
        prefix = blob[pos : pos + CHUNK_LEN_FLAG_SIZE]
        assert len(prefix) == CHUNK_LEN_FLAG_SIZE
        word = int.from_bytes(prefix, "big")
        ct_len = word & CHUNK_LEN_MASK        
        is_final = bool(word & CHUNK_FINAL_BIT)
        payload_start = pos + CHUNK_LEN_FLAG_SIZE
        payload_end = payload_start + ct_len
        records.append((prefix_start, payload_end, payload_start, payload_end, is_final))
        pos = payload_end
        if is_final:
            break
    return records


def _write_bytes(path: Path, blob: bytes) -> Path:
    path.write_bytes(blob)
    return path


def _assert_decrypt_fails(enc: Path, out: Path, aes_key: bytes, aad: bytes | None = AAD):
    with pytest.raises(DecryptionError):
        _decrypt(enc, out, aes_key, aad=aad)
    assert not out.exists(), "failed decrypt must not leave a plaintext output file"


def test_chunked_file_roundtrip_multiple_chunks(tmp_path):
    src, enc, aes_key, data = _encrypt_sample(tmp_path)
    out = tmp_path / "out.bin"

    _decrypt(enc, out, aes_key)

    assert out.read_bytes() == data
    assert out.read_bytes() == src.read_bytes()


def test_empty_file_roundtrip(tmp_path):
    src, enc, aes_key, _data = _encrypt_sample(tmp_path, data=b"")
    out = tmp_path / "empty.out"

    _decrypt(enc, out, aes_key)

    assert out.read_bytes() == b""
    assert out.read_bytes() == src.read_bytes()


def test_header_bit_flip_is_detected(tmp_path):
    _src, enc, aes_key, _data = _encrypt_sample(tmp_path)
    blob = bytearray(enc.read_bytes())
    # Flip one byte in base_nonce. Header remains parseable, but every chunk AAD/nonce changes.
    blob[_header_len(blob) - 1] ^= 0x01
    bad = _write_bytes(tmp_path / "bad-header.qduck", bytes(blob))

    _assert_decrypt_fails(bad, tmp_path / "out.bin", aes_key)


def test_chunk_payload_bit_flip_is_detected(tmp_path):
    _src, enc, aes_key, _data = _encrypt_sample(tmp_path)
    blob = bytearray(enc.read_bytes())
    first = _chunk_records(blob)[0]
    payload_start = first[2]
    blob[payload_start] ^= 0x01
    bad = _write_bytes(tmp_path / "bad-payload.qduck", bytes(blob))

    _assert_decrypt_fails(bad, tmp_path / "out.bin", aes_key)


def test_missing_final_chunk_is_detected(tmp_path):
    _src, enc, aes_key, _data = _encrypt_sample(tmp_path)
    blob = enc.read_bytes()
    records = _chunk_records(blob)
    assert len(records) >= 2
    final_start = records[-1][0]
    bad = _write_bytes(tmp_path / "missing-final.qduck", blob[:final_start])

    _assert_decrypt_fails(bad, tmp_path / "out.bin", aes_key)


def test_reordered_chunks_are_detected(tmp_path):
    _src, enc, aes_key, _data = _encrypt_sample(tmp_path)
    blob = enc.read_bytes()
    records = _chunk_records(blob)
    assert len(records) >= 3
    header = blob[: _header_len(blob)]
    chunk0 = blob[records[0][0] : records[0][1]]
    chunk1 = blob[records[1][0] : records[1][1]]
    rest = blob[records[2][0] :]
    bad = _write_bytes(tmp_path / "reordered.qduck", header + chunk1 + chunk0 + rest)

    _assert_decrypt_fails(bad, tmp_path / "out.bin", aes_key)


def test_trailing_bytes_after_final_chunk_are_detected(tmp_path):
    _src, enc, aes_key, _data = _encrypt_sample(tmp_path)
    bad = _write_bytes(tmp_path / "trailing.qduck", enc.read_bytes() + b"extra")

    _assert_decrypt_fails(bad, tmp_path / "out.bin", aes_key)


def test_wrong_aad_is_detected(tmp_path):
    _src, enc, aes_key, _data = _encrypt_sample(tmp_path)

    _assert_decrypt_fails(enc, tmp_path / "out.bin", aes_key, aad=b"wrong aad")


def test_wrong_key_is_detected(tmp_path):
    _src, enc, _aes_key, _data = _encrypt_sample(tmp_path)

    _assert_decrypt_fails(enc, tmp_path / "out.bin", os.urandom(32))


def test_decrypt_file_with_private_key_uses_embedded_key_block(tmp_path):
    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)

    data = b"self-contained file" * 1000
    src = tmp_path / "plain.bin"
    enc = tmp_path / "self-contained.qduck"
    out = tmp_path / "out.bin"
    src.write_bytes(data)

    qduck.encrypt_file(
        str(src),
        str(enc),
        aes_key,
        aad=AAD,
        key_block=key_block,
        chunk_size=MIN_CHUNK_SIZE,
    )
    qduck.decrypt_file_with_private_key(str(enc), str(out), private_key, aad=AAD)

    assert out.read_bytes() == data


def test_decrypt_file_with_private_key_requires_embedded_key_block(tmp_path):
    _src, enc, _aes_key, _data = _encrypt_sample(tmp_path)
    _public_key, private_key = qduck.generate_keypair()

    with pytest.raises(DecryptionError):
        qduck.decrypt_file_with_private_key(str(enc), str(tmp_path / "out.bin"), private_key, aad=AAD)
