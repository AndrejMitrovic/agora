/*******************************************************************************

    Low level utilities to perform Schnorr signatures on Curve25519.

    Through this module, lowercase letters represent scalars and uppercase
    letters represent points. Multiplication of a scalar by a point,
    which is adding a point to itself multiple times, is represented with '*',
    e.g. `a * G`. Uppercase letters are point representations of scalars,
    that is, the scalar multipled by the generator, e.g. `r == r * G`.
    `x` is the private key, `X` is the public key, and `H()` is the Blake2b
    512 bits hash reduced to a scalar in the field.

    Following the Schnorr BIP (see links), signatures are of the form
    `(R,s)` and satisfy `s * G = R + H(X || R || m) * X`.
    `r` is refered to as the nonce and is a cryptographically randomly
    generated number that should neither be reused nor leaked.

    Signature_Aggregation:
    Since Schnorr signatures use a linear equation, they can be simply
    combined with addition, enabling `O(1)` signature verification
    time and `O(1)` and `O(1)` signature size.
    Additionally, since the `c` factor does not depend on EC operation,
    we can do batch verification, enabling us to speed up verification
    when verifying large amount of data (e.g. a block).

    See_Also:
      - https://en.wikipedia.org/wiki/Curve25519
      - https://en.wikipedia.org/wiki/Schnorr_signature
      - https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
      - https://www.secg.org/sec1-v2.pdf

    TODO:
      - Compress signature according to SEC1 v2 (Section 2.3) (#304)
      - Audit GDC and LDC generated code
      - Proper audit

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.common.crypto.Schnorr;

import agora.common.Types;
import agora.common.Hash;
import agora.common.crypto.ECC;

import std.algorithm;
import std.range;
import std.stdio;

/// Single signature example
nothrow @nogc @safe unittest
{
    Pair kp = Pair.random();
    auto signature = sign(kp, "Hello world");
    assert(verify(kp.V, signature, "Hello world"));
}

/// Returns: The accumulated values
/// Note: be aware of accumulators, when we add to a value we must
/// ensure the value was initialized with an accumulator (not T.init!)
T combine (T)(T lhs, T rhs)
    if (is(T == Point))
{
    assert(lhs != T.init || rhs != T.init);  // at least one must be initialized

    if (lhs == T.init)
        return rhs;
    else if (rhs == T.init)
        return lhs;
    else
        return lhs + rhs;
}

/// validator signature scheme
unittest
{
    import agora.common.BitField;
    import agora.common.Deserializer;
    import agora.common.Serializer;
    import std.array;
    import std.algorithm;

    /// example block structure
    static struct Block
    {
        /// Bitfield of validators which signed
        BitField validators;

        /// Contains signatures of each validator (identified by 'validators')
        Signature signature;

        /// The revealed preimages for this block
        Hash[ushort] preimages;

        /// Block data
        string data;

        /// Block hash includes the preimages
        void computeHash (scope HashDg dg) const nothrow @nogc
        {
            hashPart(this.data, dg);
        }

        public void serialize (scope SerializeDg dg) const @trusted
        {
            serializePart(this.validators, dg);
            serializePart(this.signature, dg);

            // todo: no need to serialize length, maybe
            serializePart(this.preimages.length, dg);
            foreach (idx, preimage; this.preimages)
            {
                serializePart(idx, dg);
                serializePart(preimage, dg);
            }

            serializePart(this.data, dg);
        }

        public void deserialize (scope DeserializeDg dg) @safe
        {
            deserializePart(this.validators, dg);
            deserializePart(this.signature, dg);

            size_t length;
            deserializePart(length, dg);

            foreach (_; 0 .. length)
            {
                ushort idx;
                deserializePart(idx, dg);

                Hash preimage;
                deserializePart(preimage, dg);
                this.preimages[idx] = preimage;
            }

            deserializePart(this.data, dg);
        }
    }

    Point getExpectedR (Block block, Point[] prev_pubs)
    {
        Point exp_Rs;

        foreach (idx; 0 .. block.validators.length)
        {
            if (auto image = cast(ushort)idx in block.preimages)
            {
                if (idx < prev_pubs.length)
                {
                    // expected R based on (R2 = R1 + X1)
                    auto expected_R = prev_pubs[idx] + Scalar(*image).toPoint();

                    // add it to the sum of Rs
                    exp_Rs = combine(exp_Rs, expected_R);
                }
            }
        }

        return exp_Rs;
    }

    // 8 validators
    Pair[] pair_keys;
    8.iota.each!(_ => pair_keys ~= Pair.random());

    Pair[] genRandomPairs (size_t length)
    {
        Pair[] nodes_rands;
        nodes_rands.length = 8;

        foreach (ref pair; nodes_rands)
            pair = Pair.random();

        return nodes_rands;
    }

    // these are the initial R's that were precommited in the enrollment
    Pair[] nodes_rands = genRandomPairs(8);

    // the calculated R's for each node for the previous block (always replaced,
    // but might keep a history of these in case blocks get rolled-back)
    Point[] prev_pubs;
    prev_pubs.length = 8;

    // update expected R's based on the previously finalized block
    void updateExpectedRandoms (Block block)
    {
        // update expected previous R's for each node
        foreach (idx, preimage; block.preimages)
            prev_pubs[idx] = prev_pubs[idx] + Scalar(preimage).toPoint();
    }

    // they're sorted alphabetically (for the bitmask indices)
    Point[] pub_keys = pair_keys.map!(pair => pair.V).array;
    pub_keys.sort();

    // generates consecutive rounds of hashes for the initial scalar
    // (preimages in the resulting array should be revealed from the back)
    Hash[] genPreimages (Scalar s)
    {
        Hash[] result;
        result ~= s.hashFull();

        foreach (_; 0 .. 10)
            result ~= result[$ - 1].hashFull();

        return result;
    }

    ushort getKeyIndex (Point key)
    {
        auto res = pub_keys.countUntil(key);
        assert(res >= 0);
        assert(res < ushort.max);
        return cast(ushort)res;
    }

    // sanity check
    assert(getKeyIndex(pub_keys[0]) == 0);
    assert(getKeyIndex(pub_keys[1]) == 1);

    ///
    void revealPreimage (ref Block block, Pair key_pair, Hash preimage)
    {
        auto signer_index = getKeyIndex(key_pair.V);
        block.preimages[signer_index] = preimage;
    }

    ///
    void signBlock (ref Block block, Point X, Pair key_pair, Pair rand_pair, Point[] prev_pubs)
    {
        // commitment to common R
        Point R = getExpectedR(block, prev_pubs);

        auto sig = sign(key_pair.v, X, R, rand_pair.v, block);

        block.signature.R = R;
        block.signature.s = block.signature.s + sig.s;

        auto signer_index = getKeyIndex(key_pair.V);
        block.validators[signer_index] = true;
    }

    /// Get the sum of public keys, based on the 'validators' bitfield
    Point getPublicKeys (Block block)
    {
        Point sum;

        foreach (idx, has_signed; block.validators)
        {
            if (has_signed)
                sum = combine(sum, pub_keys[idx]);
        }

        return sum;
    }

    bool validateBlock (Block block, Block prev_block, Point[] prev_pubs)
    {
        foreach (idx, preimage; block.preimages)
        {
            // missing preimage
            if (idx !in prev_block.preimages)
                return false;

            // preimage must be of the previous preimage
            if (preimage.hashFull() != prev_block.preimages[idx])
                return false;
        }

        foreach (idx, has_signed; block.validators)
        {
            if (!has_signed)
                continue;

            // this validator did not reveal the preimage, cannot sign
            if (cast(ushort)idx !in block.preimages)
                return false;
        }

        // R2 = R1 + X (previous R1 + preimage)
        Point R = getExpectedR(block, prev_pubs);
        if (block.signature.R != R)
            return false;

        Point X = getPublicKeys(block);
        auto res = verify(X, block.signature, block);

        return res;
    }

    /** enrollment data for each validator (preimages) */
    Hash[] n1_preims = genPreimages(Scalar.random());
    Hash[] n2_preims = genPreimages(Scalar.random());
    Hash[] n3_preims = genPreimages(Scalar.random());

    /// Block #1
    Block block_1;
    block_1.data = "Block #1";
    block_1.validators = BitField(8);

    // reveal the first preimage after Enrollment
    revealPreimage(block_1, pair_keys[0], n1_preims[$ - 1]);
    revealPreimage(block_1, pair_keys[1], n2_preims[$ - 1]);
    revealPreimage(block_1, pair_keys[2], n3_preims[$ - 1]);

    // this is the first calculation of R, based on the Enrollment data
    prev_pubs[getKeyIndex(pair_keys[0].V)] = nodes_rands[0].V + Scalar(n1_preims[$ - 1]).toPoint();
    prev_pubs[getKeyIndex(pair_keys[1].V)] = nodes_rands[1].V + Scalar(n2_preims[$ - 1]).toPoint();
    prev_pubs[getKeyIndex(pair_keys[2].V)] = nodes_rands[2].V + Scalar(n3_preims[$ - 1]).toPoint();

    // create the 'r' for the first revealed pre-image after enrollment
    auto n1_rand1 = nodes_rands[0].v + Scalar(n1_preims[$ - 1]);
    auto n2_rand1 = nodes_rands[1].v + Scalar(n2_preims[$ - 1]);
    auto n3_rand1 = nodes_rands[2].v + Scalar(n3_preims[$ - 1]);

    Pair n1_rand_pair1 = Pair(n1_rand1, n1_rand1.toPoint());
    Pair n2_rand_pair1 = Pair(n2_rand1, n2_rand1.toPoint());
    Pair n3_rand_pair1 = Pair(n3_rand1, n3_rand1.toPoint());

    auto all_pubs = pair_keys[0].V + pair_keys[1].V + pair_keys[2].V;

    // add signatures (todo: not validating yet, need Enrollment data struct)
    signBlock(block_1, all_pubs, pair_keys[0], n1_rand_pair1, prev_pubs);
    signBlock(block_1, all_pubs, pair_keys[1], n2_rand_pair1, prev_pubs);
    signBlock(block_1, all_pubs, pair_keys[2], n3_rand_pair1, prev_pubs);

    /// Block #2
    Block block_2;
    block_2.data = "Block #2";
    block_2.validators = BitField(8);

    // reveal the second preimage after Enrollment
    revealPreimage(block_2, pair_keys[0], n1_preims[$ - 2]);
    revealPreimage(block_2, pair_keys[1], n2_preims[$ - 2]);
    revealPreimage(block_2, pair_keys[2], n3_preims[$ - 2]);

    // calculate the new 'r' after the second preimage was revealed
    auto n1_rand2 = n1_rand_pair1.v + Scalar(n1_preims[$ - 2]);
    auto n2_rand2 = n2_rand_pair1.v + Scalar(n2_preims[$ - 2]);
    auto n3_rand2 = n3_rand_pair1.v + Scalar(n3_preims[$ - 2]);

    Pair n1_rand_pair2 = Pair(n1_rand2, n1_rand2.toPoint());
    Pair n2_rand_pair2 = Pair(n2_rand2, n2_rand2.toPoint());
    Pair n3_rand_pair2 = Pair(n3_rand2, n3_rand2.toPoint());

    writefln("R1 + R2 + R3: %s",
        n1_rand_pair2.V + n2_rand_pair2.V + n3_rand_pair2.V);

    writefln("R1: %s", n1_rand_pair2.V);
    writefln("R2: %s", n2_rand_pair2.V);
    writefln("R3: %s", n3_rand_pair2.V);

    /// signing & validation for each node
    signBlock(block_2, all_pubs, pair_keys[0], n1_rand_pair2, prev_pubs);
    writefln("Block 2 R: %s", block_2.signature.R);
    assert(!validateBlock(block_2, block_1, prev_pubs));

    signBlock(block_2, all_pubs, pair_keys[1], n2_rand_pair2, prev_pubs);
    assert(!validateBlock(block_2, block_1, prev_pubs));
    writefln("Block 2 R: %s", block_2.signature.R);

    signBlock(block_2, all_pubs, pair_keys[2], n3_rand_pair2, prev_pubs);
    assert(validateBlock(block_2, block_1, prev_pubs));
    writefln("Block 2 R: %s", block_2.signature.R);

    updateExpectedRandoms(block_2);

    /// Block #3
    Block block_3;
    block_3.data = "Block #3";
    block_3.validators = BitField(8);

    // reveal the third preimage after Enrollment
    revealPreimage(block_3, pair_keys[0], n1_preims[$ - 3]);
    revealPreimage(block_3, pair_keys[1], n2_preims[$ - 3]);
    revealPreimage(block_3, pair_keys[2], n3_preims[$ - 3]);

    // calculate the new 'r' after the third preimage was revealed
    auto n1_rand3 = n1_rand_pair2.v + Scalar(n1_preims[$ - 3]);
    auto n2_rand3 = n2_rand_pair2.v + Scalar(n2_preims[$ - 3]);
    auto n3_rand3 = n3_rand_pair2.v + Scalar(n3_preims[$ - 3]);

    Pair n1_rand_pair3 = Pair(n1_rand3, n1_rand3.toPoint());
    Pair n2_rand_pair3 = Pair(n2_rand3, n2_rand3.toPoint());
    Pair n3_rand_pair3 = Pair(n3_rand3, n3_rand3.toPoint());

    /// signing & validation for each node
    signBlock(block_3, all_pubs, pair_keys[0], n1_rand_pair3, prev_pubs);
    assert(!validateBlock(block_3, block_2, prev_pubs));

    signBlock(block_3, all_pubs, pair_keys[1], n2_rand_pair3, prev_pubs);
    assert(!validateBlock(block_3, block_2, prev_pubs));

    signBlock(block_3, all_pubs, pair_keys[2], n3_rand_pair3, prev_pubs);
    assert(validateBlock(block_3, block_2, prev_pubs));

    updateExpectedRandoms(block_3);

    /// Block #4
    Block block_4;
    block_4.data = "Block #4";
    block_4.validators = BitField(8);

    // reveal the fourth preimage after Enrollment
    // note: node 3 did not reveal a preimage!
    revealPreimage(block_4, pair_keys[0], n1_preims[$ - 4]);
    revealPreimage(block_4, pair_keys[1], n2_preims[$ - 4]);

    // calculate the new 'r' after the fourth preimage was revealed
    auto n1_rand4 = n1_rand_pair3.v + Scalar(n1_preims[$ - 4]);
    auto n2_rand4 = n2_rand_pair3.v + Scalar(n2_preims[$ - 4]);
    auto n3_rand4 = n3_rand_pair3.v + Scalar(n3_preims[$ - 4]);

    Pair n1_rand_pair4 = Pair(n1_rand4, n1_rand4.toPoint());
    Pair n2_rand_pair4 = Pair(n2_rand4, n2_rand4.toPoint());
    Pair n3_rand_pair4 = Pair(n3_rand4, n3_rand4.toPoint());

    auto partial_pubs = pair_keys[0].V + pair_keys[1].V;

    /// signing & validation for node 1
    signBlock(block_4, partial_pubs, pair_keys[0], n1_rand_pair4, prev_pubs);
    assert(!validateBlock(block_4, block_3, prev_pubs));

    /// signing & validation for node 2
    signBlock(block_4, partial_pubs, pair_keys[1], n2_rand_pair4, prev_pubs);
    assert(validateBlock(block_4, block_3, prev_pubs));

    /// node 3 revealed preimage too late!
    {
        auto dup_block = block_4.serializeFull.deserializeFull!Block;
        assert(validateBlock(dup_block, block_3, prev_pubs));

        // too late!
        revealPreimage(dup_block, pair_keys[2], n3_preims[$ - 4]);
        assert(!validateBlock(dup_block, block_3, prev_pubs));
    }

    updateExpectedRandoms(block_4);

    /// Block #5
    /// Test-case 1: Missing preimage in previous block => cannot sign this block
    Block block_5;
    block_5.data = "Block #5";
    block_5.validators = BitField(8);

    // reveal the fifth preimage after Enrollment
    revealPreimage(block_5, pair_keys[0], n1_preims[$ - 5]);
    revealPreimage(block_5, pair_keys[1], n2_preims[$ - 5]);
    revealPreimage(block_5, pair_keys[2], n3_preims[$ - 5]);

    // calculate the new 'r' after the fifth preimage was revealed
    auto n1_rand5 = n1_rand_pair4.v + Scalar(n1_preims[$ - 5]);
    auto n2_rand5 = n2_rand_pair4.v + Scalar(n2_preims[$ - 5]);
    auto n3_rand5 = n3_rand_pair4.v + Scalar(n3_preims[$ - 5]);

    Pair n1_rand_pair5 = Pair(n1_rand5, n1_rand5.toPoint());
    Pair n2_rand_pair5 = Pair(n2_rand5, n2_rand5.toPoint());
    Pair n3_rand_pair5 = Pair(n3_rand5, n3_rand5.toPoint());

    // #add signature of node 1
    signBlock(block_5, partial_pubs, pair_keys[0], n1_rand_pair5, prev_pubs);

    // will not pass validation, node 3 revealed its preimage *now*,
    // but it did not reveal the *previous* preimage in the last block
    assert(!validateBlock(block_5, block_4, prev_pubs));

    /// Test-case 2: Wrong preimage => cannot sign block
    block_5 = Block.init;
    block_5.data = "Block #5";
    block_5.validators = BitField(8);

    // #1 reveal the fifth preimage after Enrollment
    revealPreimage(block_5, pair_keys[0], n1_preims[$ - 5]);
    revealPreimage(block_5, pair_keys[1], n2_preims[$ - 4]);  // wrong preimage!

    // #3.1 add signature of node 1 (fails)
    signBlock(block_5, partial_pubs, pair_keys[0], n1_rand_pair5, prev_pubs);
    assert(!validateBlock(block_5, block_4, prev_pubs));

    // #3.2 add signature of node 2 (fails)
    signBlock(block_5, partial_pubs, pair_keys[1], n2_rand_pair5, prev_pubs);
    assert(!validateBlock(block_5, block_4, prev_pubs));

    /// Test-case 3: Only nodes which revealed all previous preimages signed => ok
    block_5 = Block.init;
    block_5.data = "Block #5";
    block_5.validators = BitField(8);

    // #1 reveal the fifth preimage after Enrollment
    revealPreimage(block_5, pair_keys[0], n1_preims[$ - 5]);
    revealPreimage(block_5, pair_keys[1], n2_preims[$ - 5]);

    // #3.1 add signature of node 1 (doesn't pass yet)
    signBlock(block_5, partial_pubs, pair_keys[0], n1_rand_pair5, prev_pubs);
    assert(!validateBlock(block_5, block_4, prev_pubs));

    // #3.2 add signature of node 2 (passes)
    signBlock(block_5, partial_pubs, pair_keys[1], n2_rand_pair5, prev_pubs);
    assert(validateBlock(block_5, block_4, prev_pubs));

    updateExpectedRandoms(block_5);
}

/// Multi-signature example
nothrow @nogc @safe unittest
{
    // Setup
    static immutable string secret = "BOSAGORA for the win";
    Pair kp1 = Pair.random();
    Pair kp2 = Pair.random();
    Pair R1 = Pair.random();
    Pair R2 = Pair.random();
    Point R = R1.V + R2.V;
    Point X = kp1.V + kp2.V;

    auto sig1 = sign(kp1.v, X, R, R1.v, secret);
    auto sig2 = sign(kp2.v, X, R, R2.v, secret);
    auto sig3 = Signature(R, sig1.s + sig2.s);

    // No one can verify any of those individually
    assert(!verify(kp1.V, sig1, secret));
    assert(!verify(kp1.V, sig2, secret));
    assert(!verify(kp2.V, sig2, secret));
    assert(!verify(kp2.V, sig1, secret));
    assert(!verify(kp1.V, sig3, secret));
    assert(!verify(kp2.V, sig3, secret));

    // But multisig works
    assert(verify(X, sig3, secret));
}

/// Represent a signature (R, s)
public struct Signature
{
    /// Commitment
    public Point R;
    /// Proof
    public Scalar s;
}

///
unittest
{
    import agora.common.Deserializer;
    import agora.common.Serializer;

    const KP = Pair.random();
    auto signature = Signature(KP.V, KP.v);
    auto bytes = signature.serializeFull();
    assert(bytes.deserializeFull!Signature == signature);
}

/// Represent the message to hash (part of `c`)
public struct Message (T)
{
    public Point X;
    public Point R;
    public T     message;
}


/// Contains a scalar and its projection on the elliptic curve (`v` and `v.G`)
public struct Pair
{
    /// A PRNGenerated number
    public Scalar v;
    /// v.G
    public Point V;

    /// Generate a random value `v` and a point on the curve `V` where `V = v.G`
    public static Pair random () nothrow @nogc @safe
    {
        Scalar sc = Scalar.random();
        return Pair(sc, sc.toPoint());
    }
}

/// Single-signer trivial API
public Signature sign (T) (const ref Pair kp, auto ref T data)
    nothrow @nogc @safe
{
    const R = Pair.random();
    return sign!T(kp.v, kp.V, R.V, R.v, data);
}

/// Single-signer privkey API
public Signature sign (T) (const ref Scalar privateKey, T data)
    nothrow @nogc @safe
{
    const R = Pair.random();
    return sign!T(privateKey, privateKey.toPoint(), R.V, R.v, data);
}

/// Complex API, allow multisig
public Signature sign (T) (
    const ref Scalar x, const ref Point X,
    const ref Point R, const ref Scalar r,
    auto ref T data)
    nothrow @nogc @trusted
{
    /*
      G := Generator point:
      15112221349535400772501151409588531511454012693041857206046113283949847762202,
      46316835694926478169428394003475163141307993866256225615783033603165251855960
      x := private key
      X := public key (x.G)
      r := random number
      R := commitment (r.G)
      c := Hash(X || R || message)

      Proof = (R, s)
      Signature/Verify: R + c*X == s.G
      Multisig:
      R = (r0 + r1 + rn).G == (R0 + R1 + Rn)
      X = (X0 + X1 + Xn)
      To get `c`, need to precommit `R`
     */
    // Compute the challenge and reduce the hash to a scalar
    Scalar c = hashFull(Message!T(X, R, data));
    // Compute `s` part of the proof
    Scalar s = r + (c * x);
    return Signature(R, s);
}

/*******************************************************************************

    Verify that a signature matches the provided data

    Params:
      T = Type of data being signed
      X = The point corresponding to the public key
      s = Signature to verify
      data = Data to sign (the hash will be signed)

    Returns:
      Whether or not the signature is valid for (X, s, data).

*******************************************************************************/

public bool verify (T) (const ref Point X, const ref Signature s, auto ref T data)
    nothrow @nogc @trusted
{
    // Compute the challenge and reduce the hash to a scalar
    Scalar c = hashFull(Message!T(X, s.R, data));
    // Compute `R + c*X`
    Point RcX = s.R + (c * X);
    /// Compute `s.G`
    auto S = s.s.toPoint();
    return S == RcX;
}

///
nothrow @nogc @safe unittest
{
    Scalar key = Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`);
    Pair kp = Pair(key, key.toPoint());
    auto signature = sign(kp, "Hello world");
    assert(verify(kp.V, signature, "Hello world"));
}

nothrow @nogc @safe unittest
{
    Scalar key = Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`);
    Pair kp = Pair(key, key.toPoint());
    auto signature = sign(kp, "Hello world.");
    assert(!verify(kp.V, signature, "Hello world"));
}

nothrow @nogc @safe unittest
{
    static immutable string secret = "BOSAGORA for the win";
    Pair kp1 = Pair.random();
    Pair kp2 = Pair.random();
    auto sig1 = sign(kp1, secret);
    auto sig2 = sign(kp2, secret);
    assert(verify(kp1.V, sig1, secret));
    assert(!verify(kp1.V, sig2, secret));
    assert(verify(kp2.V, sig2, secret));
    assert(!verify(kp2.V, sig1, secret));
}
