#!/usr/bin/env python3
"""テストベクタ(spec/vectors/protocol.json)を作る。

参照実装を使わず、規格の文章(docs/spec.md)だけから、Python の標準の部品と、下の小さな暗号の実装で組み立てる。
実装の出力を写さないため。暗号の部品は、作る前に RFC の例と Noise の公開のテストベクタで確かめる。

  python3 tools/gen-vectors.py
"""
import hashlib
import hmac as hmac_mod
import copy
import json
import os
import zlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')

# ---- X25519(RFC 7748) ----
P = 2**255 - 19
A24 = 121665


def x25519(k, u):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    scalar = int.from_bytes(k, 'little')
    u = int.from_bytes(u, 'little') & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (scalar >> t) & 1
        if swap ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, P - 2, P) % P).to_bytes(32, 'little')


BASE = bytes([9]) + bytes(31)


# ---- ChaCha20-Poly1305(RFC 8439) ----
def rotl(v, n):
    return ((v << n) & 0xffffffff) | (v >> (32 - n))


def chacha_block(key, counter, nonce):
    state = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    state += [int.from_bytes(key[i:i + 4], 'little') for i in range(0, 32, 4)]
    state += [counter] + [int.from_bytes(nonce[i:i + 4], 'little') for i in range(0, 12, 4)]
    x = state[:]

    def qr(a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xffffffff
        x[d] = rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xffffffff
        x[b] = rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return b''.join(((x[i] + state[i]) & 0xffffffff).to_bytes(4, 'little') for i in range(16))


def chacha_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], 'little')
    acc, p = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = (acc + int.from_bytes(block + b'\x01', 'little')) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


def pad16(b):
    return bytes((16 - len(b) % 16) % 16)


def aead_encrypt(key, nonce, ad, pt):
    otk = chacha_block(key, 0, nonce)[:32]
    ct = chacha_xor(key, 1, nonce, pt)
    mac = poly1305(otk, ad + pad16(ad) + ct + pad16(ct) + len(ad).to_bytes(8, 'little') + len(ct).to_bytes(8, 'little'))
    return ct + mac


def aead_decrypt(key, nonce, ad, ct):
    otk = chacha_block(key, 0, nonce)[:32]
    body, tag = ct[:-16], ct[-16:]
    mac = poly1305(otk, ad + pad16(ad) + body + pad16(body) + len(ad).to_bytes(8, 'little') + len(body).to_bytes(8, 'little'))
    assert mac == tag, 'タグが合わない'
    return chacha_xor(key, 1, nonce, body)


# ---- Noise(規格 6 章) ----
def sha256(b):
    return hashlib.sha256(b).digest()


def hkdf2(ck, ikm):
    temp = hmac_mod.new(ck, ikm, hashlib.sha256).digest()
    o1 = hmac_mod.new(temp, b'\x01', hashlib.sha256).digest()
    o2 = hmac_mod.new(temp, o1 + b'\x02', hashlib.sha256).digest()
    return o1, o2


class Cipher:
    def __init__(self, k=None):
        self.k, self.n = k, 0

    def nonce(self):
        return bytes(4) + self.n.to_bytes(8, 'little')

    def enc(self, ad, pt):
        if self.k is None:
            return pt
        out = aead_encrypt(self.k, self.nonce(), ad, pt)
        self.n += 1
        return out

    def dec(self, ad, ct):
        if self.k is None:
            return ct
        out = aead_decrypt(self.k, self.nonce(), ad, ct)
        self.n += 1
        return out


class Hs:
    """Noise_XX_25519_ChaChaPoly_SHA256 の片側"""

    def __init__(self, initiator, s, e, prologue):
        name = b'Noise_XX_25519_ChaChaPoly_SHA256'
        self.init, self.s, self.e = initiator, s, e
        self.spub, self.epub = x25519(s, BASE), x25519(e, BASE)
        self.h = name if len(name) == 32 else sha256(name)
        self.ck = self.h
        self.c = Cipher()
        self.mix_hash(prologue)
        self.re = self.rs = None
        self.send = self.recv = None
        self.step = 0

    def mix_hash(self, d):
        self.h = sha256(self.h + d)

    def mix_key(self, ikm):
        self.ck, k = hkdf2(self.ck, ikm)
        self.c = Cipher(k)

    def eh(self, pt):
        ct = self.c.enc(self.h, pt)
        self.mix_hash(ct)
        return ct

    def dh_(self, ct):
        pt = self.c.dec(self.h, ct)
        self.mix_hash(ct)
        return pt

    def split(self):
        k1, k2 = hkdf2(self.ck, b'')
        a, b = Cipher(k1), Cipher(k2)
        self.send, self.recv = (a, b) if self.init else (b, a)

    def write(self, payload):
        if self.step == 0:              # -> e
            out = self.epub
            self.mix_hash(self.epub)
        elif self.step == 1:            # <- e, ee, s, es
            out = self.epub
            self.mix_hash(self.epub)
            self.mix_key(x25519(self.e, self.re))
            out += self.eh(self.spub)
            self.mix_key(x25519(self.s, self.re))
        else:                           # -> s, se
            out = self.eh(self.spub)
            self.mix_key(x25519(self.s, self.re))
        out += self.eh(payload)
        self.step += 1
        if self.step == 3:
            self.split()
        return out

    def read(self, msg):
        if self.step == 0:
            self.re, msg = msg[:32], msg[32:]
            self.mix_hash(self.re)
        elif self.step == 1:
            self.re, msg = msg[:32], msg[32:]
            self.mix_hash(self.re)
            self.mix_key(x25519(self.e, self.re))
            self.rs, msg = self.dh_(msg[:48]), msg[48:]
            self.mix_key(x25519(self.e, self.rs))
        else:
            self.rs, msg = self.dh_(msg[:48]), msg[48:]
            self.mix_key(x25519(self.e, self.rs))
        pt = self.dh_(msg)
        self.step += 1
        if self.step == 3:
            self.split()
        return pt


def self_check():
    """下の部品を外の出典の値で確かめる"""
    h = bytes.fromhex
    # RFC 7748 6.1
    a = h('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    b = h('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
    assert x25519(a, BASE) == h('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
    assert x25519(a, x25519(b, BASE)) == h('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
    # RFC 8439 2.8.2
    key = h('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
    ct = aead_encrypt(key, h('070000004041424344454647'), h('50515253c0c1c2c3c4c5c6c7'),
                      b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
    assert ct[:16] == h('d31a8d34648e60db7b86afbc53ef7ec2') and ct[-16:] == h('1ae10b594f09e26a7e902ecbd0600691')
    assert zlib.crc32(b'123456789') == 0xcbf43926
    # Noise の公開のテストベクタ
    with open(os.path.join(ROOT, 'spec', 'vectors', 'noise_xx_25519_chachapoly_sha256.json'), encoding='utf8') as f:
        v = json.load(f)['vector']
    get = lambda *names: next(h(v[n]) for n in names if n in v)
    pro = get('init_prologue')
    i = Hs(True, get('init_static'), get('init_ephemeral'), pro)
    r = Hs(False, get('resp_static'), get('resp_ephemeral'), pro)
    for n, m in enumerate(v['messages'][:3]):
        w, q = (i, r) if n % 2 == 0 else (r, i)
        c = w.write(h(m['payload']))
        assert c == h(m['ciphertext']), f'Noise のメッセージ {n}'
        assert q.read(c) == h(m['payload'])
    assert i.h == h(v['handshake_hash'])


# ---- フレーム・トランスポート(規格 4・5 章) ----
def cobs(data):
    out = bytearray([0])
    code_at, code = 0, 1
    for i, b in enumerate(data):
        if b == 0:
            out[code_at] = code
            code_at, code = len(out), 1
            out.append(0)
            continue
        out.append(b)
        code += 1
        if code == 0xff and i + 1 < len(data):
            out[code_at] = code
            code_at, code = len(out), 1
            out.append(0)
    out[code_at] = code
    return bytes(out)


def uart_unit(kind, seq, body=b''):
    inner = bytes([kind, seq]) + body
    return cobs(inner + zlib.crc32(inner).to_bytes(4, 'big')) + b'\x00'


def tcp_frame(frame):
    return len(frame).to_bytes(2, 'big') + frame


def fingerprint(pub):
    alpha = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    bits = int.from_bytes(sha256(pub)[:10], 'big')
    s = ''.join(alpha[(bits >> (75 - 5 * i)) & 31] for i in range(16))
    return '-'.join(s[i:i + 4] for i in range(0, 16, 4))


# ---- メッセージの分け方(規格 7 章) ----
OPS = dict(PUT=1, GET=2, DATA=3, RESULT=4, AVAIL=5, INFO=6, TIME=7, PING=8)
MORE, RESPONSE = 1, 2


def split_message(body, peer_max):
    room = peer_max - 2 - 4 - 16
    lines = [l + b'\r\n' for l in body.split(b'\r\n')[:-1]] if body else []
    chunks, cur = [], b''
    for l in lines:
        if len(cur) + len(l) > room:
            chunks.append(cur)
            cur = b''
        cur += l
    chunks.append(cur)
    return chunks


class Transcript:
    def __init__(self):
        self.steps = []
        self.seq = {'device': 0, 'host': 0}

    def add(self, sender, frame, note):
        s = self.seq[sender]
        self.seq[sender] = (s + 1) & 0xff
        receiver = 'host' if sender == 'device' else 'device'
        self.steps.append({
            'from': sender, 'note': note, 'frame': frame.hex(), 'tcp': tcp_frame(frame).hex(),
            'uart': uart_unit(0, s, frame).hex(), 'uartAck': uart_unit(1, s).hex(), 'ackFrom': receiver,
        })


def session_vector():
    h = bytes.fromhex
    dev_s, dev_e = bytes(range(0x10, 0x30)), bytes(range(0x30, 0x50))
    host_s, host_e = bytes(range(0x50, 0x70)), bytes(range(0x70, 0x90))
    prologue = b'optical-lab-device-protocol 1'
    dev_caps = b'VER=1.0\r\nDEV=EDG\r\nVEN=TEST\r\nMODEL=V1\r\nMAXFRAME=512\r\nLABELS=JOB;DBL;TRCFMT;R\r\nTRACE=4;E\r\n'
    host_caps = b'VER=1.0\r\nDEV=HST\r\nVEN=TEST\r\nMODEL=H1\r\nMAXFRAME=512\r\n'
    d, s = Hs(True, dev_s, dev_e, prologue), Hs(False, host_s, host_e, prologue)
    t = Transcript()

    def hs(sender, typ, payload, note):
        w, r = (d, s) if sender == 'device' else (s, d)
        body = w.write(payload)
        assert r.read(body) == payload
        t.add(sender, bytes([1, typ]) + body, note)

    hs('device', 1, b'', 'ハンドシェイクの 1 つめ')
    hs('host', 2, host_caps, 'ハンドシェイクの 2 つめとホストのケイパビリティ')
    hs('device', 3, dev_caps, 'ハンドシェイクの 3 つめと機器のケイパビリティ')
    assert d.h == s.h

    def msg(sender, op, req, flags, body, note):
        w, r = (d, s) if sender == 'device' else (s, d)
        chunks = split_message(body, 512)
        for i, c in enumerate(chunks):
            plain = bytes([op]) + req.to_bytes(2, 'big') + bytes([flags | (MORE if i < len(chunks) - 1 else 0)]) + c
            head = bytes([1, 16])
            ct = w.send.enc(head, plain)
            assert r.recv.dec(head, ct) == plain
            frame = head + ct
            assert len(frame) <= 512
            t.add(sender, frame, f'{note}({i + 1}/{len(chunks)})')

    msg('host', OPS['RESULT'], 0, RESPONSE, b'STATUS=0\r\n', '受け入れの通知')
    radii = ';'.join(str(2400 + i) for i in range(11))
    put_lines = ['JOB=V-1', 'DBL=18.00', 'TRCFMT=1;66;E;R;F'] + [f'R={radii}'] * 6
    put = ''.join(l + '\r\n' for l in put_lines).encode()
    msg('device', OPS['PUT'], 1, 0, put, 'PUT')
    msg('host', OPS['RESULT'], 1, RESPONSE, b'STATUS=0\r\n', 'PUT の応答')
    msg('device', OPS['GET'], 2, 0, b'JOB=V-2\r\n', 'GET')
    data_lines = ['JOB=V-2', 'DBL=18.00', 'FOO=1', 'TRCFMT=1;132;E;R;F'] + [f'R={radii}'] * 12
    data = ''.join(l + '\r\n' for l in data_lines).encode()
    msg('host', OPS['DATA'], 2, RESPONSE, data, 'GET の応答')
    result = b'JOB=V-2\r\nSTATUS=0\r\nIGNORED=FOO\r\n'
    msg('device', OPS['RESULT'], 3, 0, result, 'RESULT')
    msg('host', OPS['RESULT'], 3, RESPONSE, b'STATUS=0\r\n', 'RESULT の応答')
    def guard(victim, req):
        """UART の使用中(規格 4 章): 暗号で確かめられないフレームを捨て、続く正しい PING に答える"""
        g = Transcript()
        g.seq = dict(t.seq)
        dd, ss = copy.deepcopy(d), copy.deepcopy(s)
        attacker = 'host' if victim == 'device' else 'device'
        a, v = (ss, dd) if victim == 'device' else (dd, ss)
        head = bytes([1, 16])
        g.add(attacker, bytes([1, 127, 2]), '失敗のフレーム(認証されないので捨てる)')
        g.add(attacker, bytes([1, 2 if victim == 'device' else 3]) + bytes(48), 'ハンドシェイクのフレーム(捨てる)')
        g.add(attacker, bytes([2, 16]) + bytes(20), 'バージョンの違うフレーム(捨てる)')
        ping = bytes([OPS['PING']]) + req.to_bytes(2, 'big') + bytes([0])
        bad = bytearray(copy.deepcopy(a.send).enc(head, ping))
        bad[-1] ^= 1
        g.add(attacker, head + bytes(bad), '解けないデータのフレーム(捨て、シーケンス番号を進めない)')
        ct = a.send.enc(head, ping)
        assert v.recv.dec(head, ct) == ping
        g.add(attacker, head + ct, 'PING')
        pong = bytes([OPS['PING']]) + req.to_bytes(2, 'big') + bytes([RESPONSE])
        ct = v.send.enc(head, pong)
        assert a.recv.dec(head, ct) == pong
        g.add(victim, head + ct, 'PING の応答')
        return g.steps

    uart_guard = {'device': guard('device', 1), 'host': guard('host', 4)}
    return {
        'device': {'static': dev_s.hex(), 'ephemeral': dev_e.hex(), 'public': d.spub.hex(), 'fingerprint': fingerprint(d.spub), 'caps': dev_caps.decode()},
        'host': {'static': host_s.hex(), 'ephemeral': host_e.hex(), 'public': s.spub.hex(), 'fingerprint': fingerprint(s.spub), 'caps': host_caps.decode()},
        'prologue': prologue.decode(),
        'handshakeHash': d.h.hex(),
        'put': put.decode(), 'get': 'JOB=V-2\r\n', 'data': data.decode(), 'result': result.decode(),
        'steps': t.steps,
        'uartGuard': uart_guard,
    }


def capability_vectors():
    """REQUIRE= の判定(規格 9 章): 相手の REQUIRE が自分の EXT に無いか、自分の REQUIRE が相手の EXT に無ければ理由 5"""
    def values(lines, label):
        out = set()
        for l in lines:
            k, _, v = l.partition('=')
            if k == label:
                out.update(x for x in v.split(';') if x)
        return out

    cases = [
        ('ホストが求める拡張を機器が持たない', ['REQUIRE=ACME'], []),
        ('機器が求める拡張をホストが持たない', [], ['REQUIRE=ACME']),
        ('ホストが求める拡張を機器が持つ', ['REQUIRE=ACME'], ['EXT=ACME']),
        ('求める拡張を行を重ねて持つ', ['REQUIRE=BETA;ACME', 'EXT=X'], ['EXT=ACME', 'EXT=BETA;C']),
        ('2 行目の REQUIRE が満たされない', ['REQUIRE=ACME', 'REQUIRE=BETA'], ['EXT=ACME']),
        ('互いに求め合って、どちらも持つ', ['EXT=HST1', 'REQUIRE=DEV1'], ['EXT=DEV1', 'REQUIRE=HST1']),
        ('名前空間を付けた項目は知らなければ無視する', [], ['ACME:X=1']),
    ]
    out = []
    for name, host, device in cases:
        missing = (values(host, 'REQUIRE') - values(device, 'EXT')) | (values(device, 'REQUIRE') - values(host, 'EXT'))
        out.append({'name': name, 'host': host, 'device': device, 'fail': 5 if missing else 0})
    return out


def main():
    self_check()
    samples = [b'\x00', b'\x00\x00', b'\x11\x22\x00\x33', bytes(range(1, 255)), bytes(range(1, 256)), b'', b'\x00' * 300]
    v = {
        'about': 'tools/gen-vectors.py が規格の文章から作ったテストベクタ。手で直さない',
        'cobs': [{'raw': b.hex(), 'encoded': cobs(b).hex()} for b in samples],
        'crc32': [{'text': t, 'crc': f'{zlib.crc32(t.encode()):08x}'} for t in ['123456789', 'optical-lab-device-protocol']],
        'tcp': [{'frame': '011000', 'wire': '0003011000'}],
        'uart': [
            {'kind': 0, 'seq': 0, 'body': '011000', 'wire': uart_unit(0, 0, bytes.fromhex('011000')).hex()},
            {'kind': 1, 'seq': 7, 'body': '', 'wire': uart_unit(1, 7).hex()},
            {'kind': 0, 'seq': 255, 'body': '0000', 'wire': uart_unit(0, 255, b'\x00\x00').hex()},
        ],
        'fingerprint': [{'public': bytes(32).hex(), 'fingerprint': fingerprint(bytes(32))}, {'public': bytes(range(32)).hex(), 'fingerprint': fingerprint(bytes(range(32)))}],
        'session': session_vector(),
        'capabilities': capability_vectors(),
    }
    out = os.path.join(ROOT, 'spec', 'vectors', 'protocol.json')
    with open(out, 'w', encoding='utf8', newline='\n') as f:
        json.dump(v, f, ensure_ascii=False, indent=1)
        f.write('\n')
    print(f"{out}: {len(v['session']['steps'])} フレーム")


if __name__ == '__main__':
    main()
