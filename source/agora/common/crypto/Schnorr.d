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

import agora.common.Deserializer;
import agora.common.Serializer;

import std.algorithm;
import std.range;


/// Single signature example
nothrow @nogc unittest
{
    Pair kp = Pair.random();
    auto signature = sign(kp, "Hello world");
    assert(verify(kp.V, signature, "Hello world"));
}

import Agora = agora.common.crypto.Key;
import agora.common.Amount;

/// Check whether the wanted amount of blocks are
/// allowed to be signed with the given staked amount
private bool isWithinLimits ( uint num_blocks, Amount amount )
{
    // todo: Amount doesn't support division yet, discarding decimal part,
    // however we can just sum the amounts and check the integral amount later.
    return num_blocks <= (amount.integral / 40_000) * 2016 * 2;
}

///
unittest
{
    assert(isWithinLimits(2016, Amount.FreezeAmount));
    assert(isWithinLimits(4032, Amount.FreezeAmount));
    assert(!isWithinLimits(4033, Amount.FreezeAmount));
}

// K: A public key matching a frozen UTXO;
// X: The nth image of their source of randomness;
// N: A number within bounds [0; (Balance(K) / 40,000) * 2016 * 2 (tentative value)];
// R: The initial R used for signing;
// S: A schnorr signature for the message H(K, X, N, R) and the key K, using R.
struct EnrollTx
{
    Point utxo_key;            // K
    Hash nth_image;            // X (the Nth image of the scalar)
    uint num_blocks;           // N: the number of blocks allowed to sign for
    Point rand_point;          // R: the commited Point of r
    Signature signature;       // S: signature using r
}

/// Notes about Schnorr signatures:
/// signer has a secret key x, ephemeral (single-use) secret key k.
/// Publishes a public key xG, so x * G (generator).
/// A signature is the ephemeral public key kG as well:
/// s = k − ex
/// where e = H(kG || xG || message).
/// Note: Sometimes 'e' is used but it means 'c' (challenge)
/// Verified by checking:
/// sG = kG − exG
///
/// Another example:
/// Glossary
/// m - Message.
/// d = Private Key.
/// k = Random nonce
/// G = Generator Point.
/// Point = scalar*G = (x,y)
/// Public key = dG
/// s = k + e*d,
/// where k is random scalar, e is the challenge,
/// and d is the private key
///
/*
Schnorr signatures explained:

m = Message
x = Private key
G = Generator point
X = Public key (X = x*G, public key = private key * generator point)
(R, s) = Signature (R is the x co-ordinate of a random value after multiplying by the generator point, s is the signature)
H(x, y, z..) = Cryptographic Hashing function
* Capitalised letters are usually points on an Elliptic curve (except the Hashing function)
* Lower cased letters are usually scalars
====================================================================
Schnorr Signatures
====================================================================
Signature creation:
(R, s) = (r*G, r + H(X, R, m) * x)
* r is a random nonce
R = random nonce * generator point (becomes a point on the Elliptic Curve)
s = random nonce + Hash function(Users Public Key, Random point on Elliptic Curve, the message (transaction)) * Private Key

Signature verification:
s*G = R + H(X,R,m) * X
* Verification is a linear equation, both sides of the equation must be satisfied for the signature to be valid
signature * generator point = Random Point on Elliptic Curve + Hashing function(Public Key, Random Point on Elliptic Curve, message (transaction)) * Public Key
*/
unittest
{
    Hash msg_1 = "Block #1".hashFull();

    Scalar n1_r1;
    Scalar n2_r1;

    // keys (secret)
    Pair kp1 = Pair.random();
    Pair kp2 = Pair.random();

    // random points (secret)
    Pair N1_R = Pair.random();
    Pair N2_R = Pair.random();

    // these are derived from the previous block sig or previous enrollment
    Point N1_R1;
    Point N2_R1;

    // node #1
    {
        Hash[] n1_preimages;
        n1_preimages ~= N1_R.v.hashFull();
        n1_preimages ~= N1_R.v.hashFull().hashFull();

        Scalar r0 = N1_R.v;
        Scalar n1X0 = Scalar(n1_preimages[$ - 1]);
        n1_r1 = r0 + n1X0;
        N1_R1 = N1_R.V + n1X0.toPoint();
    }

    // node #2
    {
        Hash[] n2_preimages;
        n2_preimages ~= N2_R.v.hashFull();
        n2_preimages ~= N2_R.v.hashFull().hashFull();

        Scalar r0 = N2_R.v;
        Scalar n2X0 = Scalar(n2_preimages[$ - 1]);
        n2_r1 = r0 + n2X0;
        N2_R1 = N2_R.V + n2X0.toPoint();
    }

    auto R = N1_R1 + N2_R1;

    // all validator public keys
    Point PubKeys = kp1.V + kp2.V;

    // both sign on R and their own r
    Signature N1_SIG1 = sign(kp1.v, PubKeys, R, n1_r1, msg_1);
    Signature N2_SIG1 = sign(kp2.v, PubKeys, R, n2_r1, msg_1);

    // multisig for block #1
    Signature multisig_1 = Signature(R, N1_SIG1.s + N2_SIG1.s);

    assert(verify(PubKeys, multisig_1, msg_1));
}

struct AllData
{
    EnrollTx enr;
    Pair kp;  // utxo key
    Pair random_pair;   // the private r
    Hash[] preimages;
}

AllData[] alldatas;
AllData alldata () { return alldatas[0]; }

unittest
{
    import agora.consensus.data.Transaction;

    auto kp = Pair.random();    // just for utxo
    Pair R = Pair.random();     // starting random value (generated randomly)
    Scalar X = Scalar.random();

    version (none)
    {
        // this is our "utxo"
        auto tx = newCoinbaseTX(kp.address, Amount.FreezeAmount);
    }

    // we assume (but need to calculate later!) that the public key at
    // this address contains this staked amount
    const num_blocks = 4032;
    assert(isWithinLimits(num_blocks, Amount.FreezeAmount));

    Hash[] preimages;
    {
        Hash last_image = X.hashFull();
        preimages ~= last_image;
        foreach (idx; 0 .. num_blocks - 2)
        {
            last_image = last_image.hashFull();
            preimages ~= last_image;
        }
        assert(preimages.length == num_blocks - 1);
    }

    EnrollTx enr =
    {
        utxo_key   : kp.V,
        nth_image  : preimages[$ - 1],
        num_blocks : num_blocks,
        rand_point : R.V,
    };

    /// the message to sign: H(K, X, N, R)
    Hash message = hashMulti(enr.utxo_key, enr.nth_image, enr.num_blocks,
        enr.rand_point);

    auto new_r = R.v + Scalar(enr.nth_image);
    auto new_R = new_r.toPoint();

    /// the signature for the enrollment
    enr.signature = sign(kp.v, kp.V, new_R, new_r, message);

    Scalar X_Scalar = Scalar(enr.nth_image);
    Point R_Verify = enr.rand_point + X_Scalar.toPoint();

    assert(verify(kp.V, enr.signature, message));

    // must verify that node knows R
    assert(enr.signature.R == R_Verify);

    alldatas ~= AllData(enr, kp, R, preimages);
}

///
unittest
{
    import agora.common.BitField;
    import agora.common.crypto.Key;
    import agora.common.crypto.Schnorr;
    import agora.consensus.data.Block;
    import agora.consensus.data.Transaction;

    immutable Hash merkle =
        Hash(`0xdb6e67f59fe0b30676037e4970705df8287f0de38298dcc09e50a8e85413` ~
        `959ca4c52a9fa1edbe6a47cbb6b5e9b2a19b4d0877cc1f5955a7166fe6884eecd2c3`);

    immutable address = `GDD5RFGBIUAFCOXQA246BOUPHCK7ZL2NSHDU7DVAPNPTJJKVPJMNLQFW`;
    PublicKey pubkey = PublicKey.fromString(address);

    Transaction tx =
    {
        TxType.Payment,
        inputs: [ Input.init ],
        outputs: [
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
            Output(Amount(62_500_000L * 10_000_000L), pubkey),
        ],
    };

    auto validators = BitField(6);
    validators[0] = true;
    validators[2] = true;
    validators[4] = true;

    Block block =
    {
        header:
        {
            prev_block:  Hash.init,
            height:      0,
            merkle_root: merkle,
            validators:  validators,
        },
        txs: [ tx ],
        merkle_tree: [ merkle ],
    };

    auto R1 = alldata.enr.rand_point;



    // previous commited Nth hash of the preimage
    //Hash X1 = alldata.enr.nth_image;

    // previous block header contains the previous X
    //Hash message = block.header.hashFull();

    // the preimage that will be revealed
    //auto preimage = alldata.preimages[$ - 1];

    // verification
    //assert(preimage.hashFull() == X1);

    //Scalar X2 = Scalar(preimage);

    //Scalar priv_R2 = alldata.random_pair.v + X2;
    //Point pub_R2 = priv_R2.toPoint();

    //auto kp = alldata.kp;

    //block.header.signature = sign(kp.v, kp.V, pub_R2, priv_R2, message);

    ///// now we need to verify with the enrollment information
    //assert(verify(kp.V, block.header.signature, message));
}

/// Simple example
nothrow @nogc unittest
{
    static immutable string secret = "BOSAGORA for the win";
    Pair kp1 = Pair.random();
    Pair R1 = Pair.random();

    auto first = sign(kp1.v, kp1.V, R1.V, R1.v, secret);
    assert(verify(kp1.V, first, secret));
}

/// Represent a signature (R, s)
public struct Signature
{
    /// Commitment
    public Point R;
    /// Proof
    public Scalar s;

    /***************************************************************************

        Serialization

        Params:
            dg = serialize function accumulator

    ***************************************************************************/

    public void serialize (scope SerializeDg dg) const @safe
    {
        serializePart(this.R, dg);
        serializePart(this.s, dg);
    }

    /***************************************************************************

        Deserialization

        Params:
            dg = deserialize function accumulator

    ***************************************************************************/

    public void deserialize (scope DeserializeDg dg) @safe
    {
        deserializePart(this.R, dg);
        deserializePart(this.s, dg);
    }
}

///
unittest
{
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

    ///
    public void computeHash(scope HashDg dg) const nothrow @nogc
    {
        dg(this.X.data[]);
        dg(this.R.data[]);
        static if (is(T : const(ubyte)[]))
            dg(this.message);
        else
            hashPart(this.message, dg);
    }
}


/// Contains a scalar and its projection on the elliptic curve (`v` and `v.G`)
public struct Pair
{
    /// A PRNGenerated number
    public Scalar v;
    /// v.G
    public Point V;

    /// Generate a random value `v` and a point on the curve `V` where `V = v.G`
    public static Pair random () nothrow @nogc
    {
        Scalar sc = Scalar.random();
        return Pair(sc, sc.toPoint());
    }
}

/// Single-signer trivial API
public Signature sign (T) (const ref Pair kp, auto ref T data)
    nothrow @nogc
{
    const R = Pair.random();
    return sign!T(kp.v, kp.V, R.V, R.v, data);
}

/// Single-signer privkey API
public Signature sign (T) (const ref Scalar privateKey, T data)
    nothrow @nogc
{
    const R = Pair.random();
    return sign!T(privateKey, privateKey.toPoint(), R.V, R.v, data);
}

/// Complex API, allow multisig
public Signature sign (T) (
    const ref Scalar x, const ref Point X,
    const ref Point R, const ref Scalar r,
    auto ref T data)
    nothrow @nogc
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
    nothrow @nogc
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
nothrow @nogc unittest
{
    Scalar key = Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`);
    Pair kp = Pair(key, key.toPoint());
    auto signature = sign(kp, "Hello world");
    assert(verify(kp.V, signature, "Hello world"));
}

nothrow @nogc unittest
{
    Scalar key = Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`);
    Pair kp = Pair(key, key.toPoint());
    auto signature = sign(kp, "Hello world.");
    assert(!verify(kp.V, signature, "Hello world"));
}

nothrow @nogc unittest
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
