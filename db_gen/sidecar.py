#!/usr/bin/env python3
"""Hash compressed source stdin, or bind a generator census to its graph (format 1)."""
import hashlib
import lzma
import struct
import subprocess
import sys


def chunks(stream):
    while block := stream.read(1024 * 1024):
        yield block


def digest(stream):
    sha = hashlib.sha256()
    for block in chunks(stream):
        sha.update(block)
    return sha.hexdigest()


def text(value):
    value = value.encode('utf-8')
    if len(value) > 65535:
        raise ValueError('sidecar string too long')
    return struct.pack('<H', len(value)) + value


if sys.argv[1:] == ['hash']:
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    for block in chunks(sys.stdin.buffer):
        sha.update(block)
        md5.update(block)
        size += len(block)
    print(sha.hexdigest(), md5.hexdigest(), size)
elif len(sys.argv) == 8 and sys.argv[1] == 'build':
    wiki, uri, proof, graph, census, output = sys.argv[2:]
    source_sha, _, _ = open(proof).read().split()
    if not uri.startswith('https://dumps.wikimedia.org/') or len(source_sha) != 64:
        raise ValueError('invalid source binding')
    with open(graph, 'rb') as asset:
        asset_sha = digest(asset)
    with lzma.open(graph) as raw:
        header = raw.read(8)
        if header[:4] != b'WIKI' or len(header) != 8 or struct.unpack('<I', header[4:])[0] & 255 != 2:
            raise ValueError('unsupported graph')
        sha = hashlib.sha256(header)
        for block in chunks(raw):
            sha.update(block)
        raw_sha = sha.hexdigest()
    with open(census, 'rb') as records, open(output, 'xb') as target:
        policy, unicode = struct.unpack('<II', records.read(8))
        if policy != 1 or records.read(4) != b'SINF':
            raise ValueError('unsupported census')
        length = records.read(4)
        size, = struct.unpack('<I', length)
        if not 0 < size <= 65535:
            raise ValueError('invalid siteinfo')
        site = records.read(size)
        name_size, = struct.unpack('<H', site[:2])
        if len(site) != size or site[2:2 + name_size].decode('utf-8') != wiki:
            raise ValueError('census wiki mismatch')
        prefix = b'WMETAB01' + struct.pack('<4I', 1, 1, policy, unicode)
        prefix += b''.join(text(value) for value in (wiki, uri, source_sha, raw_sha, asset_sha))
        prefix += length + site
        sha = hashlib.sha256(prefix)
        process = subprocess.Popen(['zstd', '-q', '-5', '--check', '-c'], stdin=subprocess.PIPE, stdout=target)
        try:
            with process.stdin as stream:
                stream.write(prefix)
                for block in chunks(records):
                    sha.update(block)
                    stream.write(block)
                stream.write(sha.digest())
        except BaseException:
            process.wait()
            raise
        if process.wait() != 0:
            raise RuntimeError('sidecar compression failed')
else:
    sys.exit('usage: sidecar.py hash | build WIKI URI SOURCE_HASH_FILE GRAPH CENSUS OUTPUT')
