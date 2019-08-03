from secp256k1 import FLAG_ALL
from secp256k1.key import SecretKey, PublicKey
from secp256k1.pedersen import Secp256k1
import grin.aggsig as aggsig

from binascii import hexlify
from os import urandom
from _libsecp256k1 import ffi, lib

from grin.util import hasher
from hashlib import sha256


class Generator:
    def __init__(self, secp: Secp256k1):
        self.gen = ffi.new("secp256k1_generator *")
        self.secp = secp

    def __str__(self):
        return "Generator<{}>".format(self.to_hex(self.secp).decode())

    def __repr__(self):
        return self.__str__()

    def to_bytearray(self, secp: Secp256k1) -> bytearray:
        out = ffi.new("char [33]")
        res = lib.secp256k1_generator_serialize(secp.ctx, out, self.gen)
        assert res, "Unable to serialize"
        return bytearray(ffi.buffer(out, 33))

    def to_hex(self, secp: Secp256k1) -> bytes:
        return hexlify(self.to_bytearray(secp))

    @staticmethod
    def from_bytearray(secp: Secp256k1, data: bytearray):
        assert len(data) == 33, "Invalid generator size"
        g = Generator(secp)

        res = lib.secp256k1_generator_parse(secp.ctx, g.gen, bytes(data))
        assert res, "Invalid generator"
        return g

    @staticmethod
    def random(secp: Secp256k1):
        return Generator.from_seed(secp, urandom(32))

    @staticmethod
    def from_seed(secp: Secp256k1, seed: bytes) -> 'Generator':
        assert len(seed) == 32, "Seed must be 32 bytes"
        g = Generator(secp)
        res = lib.secp256k1_generator_generate(secp.ctx, g.gen, seed)
        assert res, "Failed to generate a generator"
        return g

    @staticmethod
    def from_asset_symbol(secp: Secp256k1, symbol: str):
        data = symbol.encode("utf-8")
        seed = hasher(data) # blake2b
        return Generator.from_seed(secp, seed)


def pick_generator():
    secp = Secp256k1(None, FLAG_ALL)

    # Asset generator must not be the negative of any other asset. This must be enforced when
    # the asset is created.
    #
    # Also, maybe short name squatting... like adding a salt to generate assets?
    g = Generator.from_asset_symbol(secp, "QTUM")
    data = g.to_bytearray(secp)

    g2 = Generator.from_bytearray(secp, data)
    print(g.to_hex(secp), g2.to_hex(secp))

def tx_with_multiple_assets():
    secp = Secp256k1(None, FLAG_ALL)

    # generator for qtum asset
    Q = Generator.from_asset_symbol(secp, "QTUM").gen
    # Q must not be the negative of any other asset. This must be enforced when
    # the asset is created.
    #
    # Question: How could the validator know that the commitments are created with
    # acceptable generators? Sender and receiver could collude to use the
    # negative of a generator, and hide the fact behind commitments.
    #
    # Answer: I am guessing that rangeproof can do that... parameterize on the chosen
    # asset Q. Validator just need to make sure that Q is a published asset.

    # aH + iG (sender)
    ikey = SecretKey.random(secp)  # i
    # ipubkey = ikey.to_public_key(secp)  # iG
    input = secp.commit(100, ikey)  # aH + iG

    # aQ + iG (sender)
    qikey = SecretKey.random(secp)  # qi
    # qipubkey = qikey.to_public_key(secp)  # qiG
    qinput = secp.commit(10, qikey, asset=Q)  # aQ + qiG

    # aH + oG (receiver)
    okey = SecretKey.random(secp)
    opubkey = okey.to_public_key(secp)  # oG
    output = secp.commit(100, okey)  # aH + oG

    # aQ + oG (receiver)
    qokey = SecretKey.random(secp)  # qo
    qopubkey = qokey.to_public_key(secp)  # qoG
    qoutput = secp.commit(10, qokey, asset=Q)  # aQ + qoG

    # The underlying secp256k1_pedersen_commit_sum function checks if output is INF.
    # zero = secp.commit_sum([output], [output])
    # print("zero", k.to_hex(secp)) # error

    # by convention: sum(output) + sum(neg(input))
    kernel = secp.commit_sum([output, qoutput], [input, qinput])
    kernel_pubkey = kernel.to_public_key(secp)

    ##############################
    # group signature
    ##############################

    # these are only to generate a message for signature. All participants can agree on the features of a tx.
    fee = 0
    lock_height = 0

    inonce = SecretKey.random(secp)
    inonce_pubkey = inonce.to_public_key(secp)
    sigikey = ikey.negate(secp) # input should be negated for signatures
    sigipubkey = sigikey.to_public_key(secp)

    qinonce = SecretKey.random(secp)
    qinonce_pubkey = qinonce.to_public_key(secp)
    sigqikey = qikey.negate(secp) # input should be negated for signatures
    sigqipubkey = sigqikey.to_public_key(secp)

    ononce = SecretKey.random(secp)  # nonces are also based on generator G
    ononce_pubkey = ononce.to_public_key(secp)

    qononce = SecretKey.random(secp)  # nonces are also based on generator G
    qononce_pubkey = qononce.to_public_key(secp)

    nonce_pubkeysum = PublicKey.from_combination(
        secp, [inonce_pubkey, ononce_pubkey, qinonce_pubkey, qononce_pubkey])
    pubkeysum = PublicKey.from_combination(
        secp, [opubkey, sigipubkey, qopubkey, sigqipubkey])

    # the partial sigs use secret, known only to individual signers (i.e. key, nonce)
    ipartialsig = aggsig.calculate_partial(
        secp, sigikey, inonce, pubkeysum, nonce_pubkeysum, fee, lock_height)
    qipartialsig = aggsig.calculate_partial(
        secp, sigqikey, qinonce, pubkeysum, nonce_pubkeysum, fee, lock_height)

    opartialsig = aggsig.calculate_partial(
        secp, okey, ononce, pubkeysum, nonce_pubkeysum, fee, lock_height)
    qopartialsig = aggsig.calculate_partial(
        secp, qokey, qononce, pubkeysum, nonce_pubkeysum, fee, lock_height)

    # verify that partial signatures are valid
    print("ipartialsig valid:", aggsig.verify_partial(secp, ipartialsig,
                                                      sigipubkey, pubkeysum, nonce_pubkeysum, fee, lock_height))
    print("opartialsig valid:", aggsig.verify_partial(secp, opartialsig,
                                                      opubkey, pubkeysum, nonce_pubkeysum, fee, lock_height))

    # aggregate signatures
    signature = aggsig.add_partials(
        secp, [ipartialsig, opartialsig, qipartialsig, qopartialsig], nonce_pubkeysum)
    # the final verification does not need to signature nonces
    print("aggsig is valid", aggsig.verify(
        secp, signature, pubkeysum, fee, lock_height))

    print("signature pubkey agree with committment excess:",
          kernel_pubkey.to_hex(secp) == pubkeysum.to_hex(secp))

def main():
    # TODO: implement change
    # TODO: implement fee
    # TODO: implement kernel offset
    # TODO: figure out how to generate range proofs

    secp = Secp256k1(None, FLAG_ALL)

    # generator for qtum asset
    # Q = Generator.from_asset_symbol(secp, "QTUM").gen

    # secret key is the field element
    # SecretKey.random(secp)

    # aH + iG (sender)
    ikey = SecretKey.random(secp)  # i
    ipubkey = ikey.to_public_key(secp)  # iG
    input = secp.commit(100, ikey)  # aH + iG

    # aQ + iG (sender)
    # qikey = SecretKey.random(secp)  # qi
    # qipubkey = qikey.to_public_key(secp)  # qiG
    # qinput = secp.commit(10, qikey)  # aQ + qiG

    # aH + oG (receiver)
    okey = SecretKey.random(secp)
    opubkey = okey.to_public_key(secp)  # oG
    output = secp.commit(100, okey)  # aH + oG

    # aQ + oG (receiver)
    # qokey = SecretKey.random(secp)  # qo
    # qopubkey = qokey.to_public_key(secp)  # qoG
    # qoutput = secp.commit(10, qokey)  # aQ + qoG

    # The underlying secp256k1_pedersen_commit_sum function checks if output is INF.
    # zero = secp.commit_sum([output], [output])
    # print("zero", k.to_hex(secp)) # error

    # by convention: sum(output) + sum(neg(input))
    kernel = secp.commit_sum([output], [input])
    kernel_pubkey = kernel.to_public_key(secp)

    ##############################
    # group signature
    ##############################

    # outline on how aggsig is built interactively.
    #
    # https://github.com/mimblewimble/grin/issues/399#issuecomment-352727357
    # https://lists.launchpad.net/mimblewimble/msg00087.html
    # https://lists.launchpad.net/mimblewimble/msg00091.html
    #
    # participants need to share the public nonce and public blind excess to all

    # these are only to generate a message for signature. All participants can agree on the features of a tx.
    fee = 0
    lock_height = 0

    inonce = SecretKey.random(secp)
    inonce_pubkey = inonce.to_public_key(secp)
    sigikey = ikey.negate(secp) # input should be negated for signatures
    sigipubkey = sigikey.to_public_key(secp)

    ononce = SecretKey.random(secp)  # nonces are also based on generator G
    ononce_pubkey = ononce.to_public_key(secp)

    nonce_pubkeysum = PublicKey.from_combination(
        secp, [inonce_pubkey, ononce_pubkey])
    pubkeysum = PublicKey.from_combination(
        secp, [opubkey, sigipubkey])  # NOTE: just the sum, not oG - iG

    # the partial sigs use secret, known only to individual signers (i.e. key, nonce)
    ipartialsig = aggsig.calculate_partial(
        secp, sigikey, inonce, pubkeysum, nonce_pubkeysum, fee, lock_height)
    opartialsig = aggsig.calculate_partial(
        secp, okey, ononce, pubkeysum, nonce_pubkeysum, fee, lock_height)

    # verify that partial signatures are valid
    print("ipartialsig valid:", aggsig.verify_partial(secp, ipartialsig,
                                                      sigipubkey, pubkeysum, nonce_pubkeysum, fee, lock_height))
    print("opartialsig valid:", aggsig.verify_partial(secp, opartialsig,
                                                      opubkey, pubkeysum, nonce_pubkeysum, fee, lock_height))

    # aggregate signatures
    signature = aggsig.add_partials(
        secp, [ipartialsig, opartialsig], nonce_pubkeysum)
    # the final verification does not need to signature nonces
    print("aggsig is valid", aggsig.verify(
        secp, signature, pubkeysum, fee, lock_height))

    # QUESTION: 

    # Finally, validator should check that signature is signed by kernel key.
    # 
    # kernel_pubkey and pubkeysum are the same thing, calculated in two different ways.
    #
    # kernel_pubkey is the excess by summing input/output commitments (from transaction)
    # pubkeysum is the sum of the pubkeys declared by participants to create a signature, known only to them (from slate)
    #
    print("signature pubkey agree with committment excess:",
          kernel_pubkey.to_hex(secp) == pubkeysum.to_hex(secp))


if __name__ == "__main__":
    # spick_generator()
    tx_with_multiple_assets()
    # main()
