from binascii import hexlify, unhexlify
from secp256k1 import Secp256k1 as Secp256k1_base, Message, SECRET_KEY_SIZE
from secp256k1.key import SecretKey, PublicKey
from ._libsecp256k1 import ffi, lib

PEDERSEN_COMMITMENT_SIZE = 33
MAX_PROOF_SIZE = 675
PROOF_MSG_SIZE = 64
MAX_WIDTH = 1 << 20


# Pedersen Commitment xG+vH
class Commitment:
    def __init__(self, secp):
        assert isinstance(secp, Secp256k1)
        self.commitment = ffi.new("secp256k1_pedersen_commitment *")
        self.secp = secp

    def __eq__(self, other):
        return isinstance(other, Commitment) and self.to_bytearray(self.secp) == other.to_bytearray(other.secp)

    def __str__(self):
        return "Commitment<{}>".format(self.to_hex(self.secp).decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self, secp) -> bytearray:
        assert isinstance(secp, Secp256k1)
        out = ffi.new("char [%d]" % PEDERSEN_COMMITMENT_SIZE)
        res = lib.secp256k1_pedersen_commitment_serialize(secp.ctx, out, self.commitment)
        assert res, "Unable to serialize"
        return bytearray(ffi.buffer(out, PEDERSEN_COMMITMENT_SIZE))

    def to_hex(self, secp) -> bytes:
        return hexlify(self.to_bytearray(secp))

    def to_public_key(self, secp) -> PublicKey:
        assert isinstance(secp, Secp256k1)
        obj = PublicKey(secp)
        res = lib.secp256k1_pedersen_commitment_to_pubkey(secp.ctx, obj.key, self.commitment)
        assert res, "Unable to convert to public key"
        return obj

    @staticmethod
    def from_bytearray(secp, data: bytearray):
        assert isinstance(secp, Secp256k1)
        input = bytearray([0] * PEDERSEN_COMMITMENT_SIZE)
        for i in range(min(len(data), PEDERSEN_COMMITMENT_SIZE)):
            input[i] = data[i]
        obj = Commitment(secp)
        res = lib.secp256k1_pedersen_commitment_parse(secp.ctx, obj.commitment, bytes(input))
        assert res, "Invalid commitment"
        return obj

    @staticmethod
    def from_hex(secp, data: bytes):
        return Commitment.from_bytearray(secp, bytearray(unhexlify(data)))


class RangeProof:
    def __init__(self, proof: bytearray):
        self.proof = proof
        self.proof_len = len(proof)

    def __eq__(self, other):
        return isinstance(other, RangeProof) and self.proof == other.proof

    def __str__(self):
        return "RangeProof<len={}, {}>".format(self.proof_len, hexlify(self.proof[0:8]).decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self) -> bytearray:
        return self.proof[:]

    def to_hex(self) -> bytes:
        return hexlify(bytes(self.proof))

    @staticmethod
    def from_bytearray(data: bytearray):
        assert len(data) <= MAX_PROOF_SIZE, "Invalid proof size"
        return RangeProof(data)

    @staticmethod
    def from_hex(data: bytes):
        return RangeProof.from_bytearray(bytearray(unhexlify(data)))


class Secp256k1(Secp256k1_base):
    def __init__(self, ctx, flags):
        super().__init__(ctx, flags)
        self.GENERATOR_G = ffi.new("secp256k1_generator *", [bytes([
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
            0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
            0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
            0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
        ])])
        self.GENERATOR_H = ffi.new("secp256k1_generator *", [bytes([
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
            0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
            0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
            0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
            0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
            0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
            0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
            0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
        ])])

        self.gens = lib.secp256k1_bulletproof_generators_create(self.ctx, self.GENERATOR_G, 256)

    def commit(self, value: int, blind, asset=None) -> Commitment:
        if asset == None:
            asset = self.GENERATOR_H
        obj = Commitment(self)
        res = lib.secp256k1_pedersen_commit(self.ctx, obj.commitment, bytes(blind.key), value,
                                            asset, self.GENERATOR_G)
        assert res, "Unable to commit"
        return obj

    def commit_value(self, value: int) -> Commitment:
        blind = SecretKey()
        return self.commit(value, blind)

    def commit_sum(self, positives, negatives) -> Commitment:
        pos = []
        for positive in positives:
            assert isinstance(positive, Commitment)
            pos.append(positive.commitment)
        neg = []
        for negative in negatives:
            assert isinstance(negative, Commitment)
            neg.append(negative.commitment)
        commit_sum = Commitment(self)
        res = lib.secp256k1_pedersen_commit_sum(self.ctx, commit_sum.commitment, pos, len(pos), neg, len(neg))
        assert res, "Unable to sum commitments"
        return commit_sum

    def blind_sum(self, positives, negatives) -> SecretKey:
        keys = []
        for positive in positives:
            assert isinstance(positive, SecretKey)
            keys.append(ffi.new("char []", bytes(positive.key)))
        for negative in negatives:
            assert isinstance(negative, SecretKey)
            keys.append(ffi.new("char []", bytes(negative.key)))
        sum_key = ffi.new("char []", SECRET_KEY_SIZE)
        ret = lib.secp256k1_pedersen_blind_sum(self.ctx, sum_key, keys, len(keys), len(positives))
        assert ret, "Unable to sum blinding factors"
        return SecretKey.from_bytearray(self, bytearray(ffi.buffer(sum_key, SECRET_KEY_SIZE)))

    def sign(self, secret_key: SecretKey, message: bytearray):
        assert len(message) == 32, "Invalid message length"
        signature_obj = ffi.new("secp256k1_ecdsa_signature *")
        res = lib.secp256k1_ecdsa_sign(
            self.ctx, signature_obj, bytes(message), bytes(secret_key.key), ffi.NULL, ffi.NULL
        )
        assert res, "Unable to generate signature"
        signature_ptr = ffi.new("char []", 80)
        signature_len_ptr = ffi.new("size_t *", 80)
        res = lib.secp256k1_ecdsa_signature_serialize_der(
            self.ctx, signature_ptr, signature_len_ptr, signature_obj
        )
        assert res, "Unable to DER serialize signature"
        return bytearray(ffi.buffer(signature_ptr, signature_len_ptr[0]))

    def sign_recoverable(self, secret_key: SecretKey, message: bytearray) -> bytearray:
        assert len(message) == 32, "Invalid message length"
        signature_obj = ffi.new("secp256k1_ecdsa_recoverable_signature *")
        res = lib.secp256k1_ecdsa_sign_recoverable(
            self.ctx, signature_obj, bytes(message), bytes(secret_key.key), ffi.NULL, ffi.NULL
        )
        assert res, "Unable to generate recoverable signature"
        signature_ptr = ffi.new("char []", 64)
        rec_id_ptr = ffi.new("int *")
        res = lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            self.ctx, signature_ptr, rec_id_ptr, signature_obj
        )
        assert res, "Unable to serialize recoverable signature"
        signature = bytearray(ffi.buffer(signature_ptr, 64))
        signature.append(rec_id_ptr[0])
        return signature

    def bullet_proof(self, value: int, blind: SecretKey, nonce: SecretKey, extra_data: bytearray = bytearray()) -> RangeProof:
        proof_ptr = ffi.new("char []", MAX_PROOF_SIZE)
        proof_len_ptr = ffi.new("size_t *", MAX_PROOF_SIZE)
        blind_key = ffi.new("char []", bytes(blind.key))
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        res = lib.secp256k1_bulletproof_rangeproof_prove(
            self.ctx,
            scratch,
            self.gens,
            proof_ptr,
            proof_len_ptr,
            ffi.NULL,  # multi-party: tau_x
            ffi.NULL,  # multi-party: t_one
            ffi.NULL,  # multi-party: t_two
            [value],  # value: array of values committed by the Pedersen commitments
            ffi.NULL,  # array of minimum values to prove ranges above, or NULL for all-zeroes
            [blind_key],  # blind: array of blinding factors of the Pedersen commitments (cannot be NULL)
            ffi.NULL,  # commits: only for multi-party; array of pointers to commitments
            1,  # n_commits: number of entries in the `value` and `blind` arrays
            self.GENERATOR_H,  # value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
            64,  # nbits: number of bits proven for each range
            bytes(nonce.key),  # nonce: random 32-byte seed used to derive blinding factors (cannot be NULL)
            ffi.NULL,  # private_nonce: only for multi-party; random 32-byte seed used to derive private blinding factors
            bytes(extra_data),
            len(extra_data),
            ffi.NULL
        )
        obj = RangeProof.from_bytearray(bytearray(ffi.buffer(proof_ptr, proof_len_ptr[0])))
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate bulletproof"
        return obj

    def bullet_proof_verify(self, proof: RangeProof, commit: Commitment, extra_data: bytearray = bytearray()) -> bool:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)

        proof_bytes = ffi.new("char []", bytes(proof.proof))
        # proof_bytes = ffi.new("char []", bytes(proof.to_bytearray()))

        # hmmm, len(proof_bytes) 676, one byte extra than proof.proof_len -.-
        # print("len(proof_bytes) proof.proof_len", len(proof_bytes), proof.proof_len)
        res = lib.secp256k1_bulletproof_rangeproof_verify(
            self.ctx,
            scratch,
            self.gens,
            proof_bytes,  # proof: byte-serialized rangeproof (cannot be NULL)
            proof.proof_len,  # proof.proof_len, # plen: length of the proof
            ffi.NULL,  # min_value: array of minimum values to prove ranges above, or NULL for all-zeroes
            commit.commitment,  # commit: array of pedersen commitment that this rangeproof is over (cannot be NULL)
            1,  # n_commits: number of commitments in the above array (cannot be 0)
            64,  # nbits: number of bits proven for each range
            self.GENERATOR_H,  # value_gen: generator multiplied by value in pedersen commitments (cannot be NULL)
            bytes(extra_data),
            len(extra_data),
        )

        lib.secp256k1_scratch_space_destroy(scratch)  # -> void

        return res == 1

    def bullet_proof_multisig_1(self, value: int, blind: SecretKey, commit: Commitment, common_nonce: SecretKey,
                                nonce: SecretKey, extra_data: bytearray) -> (PublicKey, PublicKey):
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        t_1 = PublicKey(self)
        t_2 = PublicKey(self)
        blind_key = ffi.new("char []", bytes(blind.key))
        res = lib.secp256k1_bulletproof_rangeproof_prove(
            self.ctx, scratch, self.gens, ffi.NULL, ffi.NULL, ffi.NULL, t_1.key, t_2.key, [value],
            ffi.NULL, [blind_key], [commit.commitment], 1, self.GENERATOR_H, 64, bytes(common_nonce.key),
            bytes(nonce.key), bytes(extra_data), len(extra_data), ffi.NULL
        )
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate multisig bulletproof"
        return t_1, t_2

    def bullet_proof_multisig_2(self, value: int, blind: SecretKey, commit: Commitment, common_nonce: SecretKey,
                                nonce: SecretKey, t_1: PublicKey, t_2: PublicKey, extra_data: bytearray) -> SecretKey:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        tau_x_ptr = ffi.new("char []", 32)
        blind_key = ffi.new("char []", bytes(blind.key))
        res = lib.secp256k1_bulletproof_rangeproof_prove(
            self.ctx, scratch, self.gens, ffi.NULL, ffi.NULL, tau_x_ptr, t_1.key, t_2.key, [value],
            ffi.NULL, [blind_key], [commit.commitment], 1, self.GENERATOR_H, 64, bytes(common_nonce.key),
            bytes(nonce.key), bytes(extra_data), len(extra_data), ffi.NULL
        )
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate multisig bulletproof"
        return SecretKey.from_bytearray(self, bytearray(ffi.buffer(tau_x_ptr, 32)))

    def bullet_proof_multisig_3(self, value: int, blind: SecretKey, commit: Commitment, common_nonce: SecretKey,
                                nonce: SecretKey, t_1: PublicKey, t_2: PublicKey, tau_x: SecretKey,
                                extra_data: bytearray) -> RangeProof:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        proof_ptr = ffi.new("char []", MAX_PROOF_SIZE)
        proof_len_ptr = ffi.new("size_t *", MAX_PROOF_SIZE)
        tau_x_ptr = ffi.new("char []", bytes(tau_x.to_bytearray()))
        blind_key = ffi.new("char []", bytes(blind.key))
        res = lib.secp256k1_bulletproof_rangeproof_prove(
            self.ctx, scratch, self.gens, proof_ptr, proof_len_ptr, tau_x_ptr, t_1.key, t_2.key,
            [value], ffi.NULL, [blind_key], [commit.commitment], 1, self.GENERATOR_H, 64, bytes(common_nonce.key),
            bytes(nonce.key), bytes(extra_data), len(extra_data), ffi.NULL
        )
        obj = RangeProof.from_bytearray(bytearray(ffi.buffer(proof_ptr, proof_len_ptr[0])))
        lib.secp256k1_scratch_space_destroy(scratch)
        assert res, "Unable to generate multisig bulletproof"
        return obj

    def verify_bullet_proof(self, commit: Commitment, proof: RangeProof, extra_data: bytearray) -> bool:
        scratch = lib.secp256k1_scratch_space_create(self.ctx, 256 * MAX_WIDTH)
        res = lib.secp256k1_bulletproof_rangeproof_verify(
            self.ctx, scratch, self.gens, bytes(proof.proof), proof.proof_len, ffi.NULL, commit.commitment,
            1, 64, self.GENERATOR_H, bytes(extra_data), len(extra_data)
        )
        lib.secp256k1_scratch_space_destroy(scratch)
        return res == 1


def ethereum_signature(data: bytearray) -> (bytes, bytes, int):
    assert len(data) == 65
    r = b"0x"+hexlify(bytes(data[:32]))
    s = b"0x"+hexlify(bytes(data[32:64]))
    v = int.from_bytes(bytes(data[64:]), "big") + 27
    return r, s, v
