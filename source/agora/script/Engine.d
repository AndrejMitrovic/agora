/*******************************************************************************

    Contains the script execution engine (non-webASM)

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Engine;

import agora.common.crypto.ECC;
import Schnorr = agora.common.crypto.Schnorr;
import agora.common.Hash;
import agora.consensus.data.Transaction;
import agora.script.Codes;
import agora.script.ScopeCondition;
import agora.script.Script;
import agora.script.Stack;

import std.bitmanip;
import std.range;
import std.traits;

version (unittest)
{
    import agora.common.crypto.ECC;
    import agora.common.crypto.Schnorr;
    import agora.common.Hash;
    import agora.utils.Test;
    import ocean.core.Test;
    import std.stdio : writefln, writeln;  // avoid importing LockType
}

/// The engine executes scripts, and returns a value or throws
public class Engine
{
    /// Conditional opcodes require the top item on the stack to be one of these
    private static immutable ubyte[1] TRUE = [OP.TRUE];
    private static immutable ubyte[1] FALSE = [OP.FALSE];

    /// historic backwards compatibility for the tests.
    /// The tests were originally written following Bitcoin script layout,
    /// but was later replaced with a lock type tag (see toLockScript()).
    version (unittest)
    private string execute (LockType lock_type, in Script lock,
        in Script unlock)
    {
        Transaction tx;
        return this.execute(lock_type, lock, unlock, tx);
    }

    /// ditto
    private string execute (LockType lock_type, in Script lock,
        in Script unlock, in Transaction tx)
    {
        return this.execute([ubyte(lock_type)] ~ lock[],
            unlock[], tx);
    }

    // tx: the transaction that's trying to spend (used for the commitment check)
    public string execute (in ubyte[] lock_bytes, in ubyte[] unlock_bytes,
        in Transaction tx)
    {
        Script lock;
        if (auto error = toLockScript(lock_bytes, lock))
            return error;

        if (auto error = lock.isInvalidSyntaxReason())
            return "Lock script error: " ~ error;

        Script unlock = Script(unlock_bytes);
        if (auto error = unlock.isInvalidSyntaxReason())
            return "Unlock script error: " ~ error;

        // todo: check script weight:
        // - max opcode length
        // - num of opcodes
        // - weight of each opcode (e.g. sig checks more expensive than ADD)
        // might want to calculate the weight in an out parameter in
        // isInvalidSyntaxReason()

        // todo: check *executed* instructions and that they don't
        // go over the configured (consensus) limit

        // todo: for witness support (BIP 141) see commit:
        // 449f9b8debcceb61a92043bc7031528a53627c47

        Stack stack;
        if (auto error = this.executeScript(unlock, stack, tx))
            return error;

        // kept in case of P2SH
        Stack unlock_stack = stack.copy();

        // todo: check for dangling ops in the bytes array for unlock
        // unlock script => only if there are no dangling operators it's valid,
        //                  but stack may have any data on it
        // lock script => only if there is a TRUE value on the stack it's valid

        if (auto error = this.executeScript(lock, stack, tx))
            return error;

        // do not move! must check before P2SH as redeem script hash is checked
        if (hasStackFailed(stack))
            return "Script failed";

        // special handling for P2SH scripts
        if (lock.isLockP2SH())
        {
            // todo: check
            // - push only opcodes
            // - empty stack
            stack = unlock_stack.copy();

            // todo: may want to make this an early return, or move the
            // stack empty check above
            assert(!stack.empty);
            Script redeem = Script(stack.pop());

            if (auto error = this.executeScript(redeem, stack, tx))
                return error;

            if (hasStackFailed(stack))
                return "Script failed";
        }

        return null;
    }

    private string executeScript (in Script script,
        ref Stack stack, in Transaction tx)
    {
        // if *any* items are false, then the current execution
        // state is false, and we continue executing next
        // instructions. however the fExec level is set to false,
        // until an ELSE or ENDIF sets it to true (I think),
        // and then we can execute code again.

        // todo: verify stack data pushes via CheckMinimalPush(),
        // it seems it's related to BIP62 where pushes can be
        // encoded in different ways. Note: BIP141 (segwit)
        // largely replaces BIP62, so we may not require
        // the validation in CheckMinimalPush(). It is likely
        // still there for compatibility reasons.

        // todo: check max stack size
        // todo: do not implement alt stack, it's unnecessary

        // todo: do not add any more support other than the bare
        // minimum for script validation. e.g. don't add OP_ADD support
        // because this requires emulating a specific virtual machine
        // platform which handles integer arithmetic the same on all platforms.

        ScopeCondition sc;
        const(ubyte)[] bytes = script[];
        while (!bytes.empty())
        {
            const OP opcode = bytes.front.toOPCode();
            bytes.popFront();

            if (opcode.isConditional())
            {
                if (auto error = handleConditional(opcode, stack, sc))
                    return error;
                continue;
            }

            // whether the current scope is executable
            // (all preceeding outer conditionals were true)
            if (!sc.isTrue())
                continue;

            switch (opcode)
            {
            case OP.TRUE:
                if (!stack.canPush(TRUE))
                    return "Stack overflow while pushing OP.TRUE";
                stack.push(TRUE);
                break;

            case OP.FALSE:
                if (!stack.canPush(FALSE))
                    return "Stack overflow while pushing OP.FALSE";
                stack.push(FALSE);
                break;

            case OP.PUSH_DATA_1:
                if (auto reason = pushToStack!(OP.PUSH_DATA_1)(stack, bytes))
                    return reason;
                break;

            case OP.PUSH_DATA_2:
                if (auto reason = pushToStack!(OP.PUSH_DATA_2)(stack, bytes))
                    return reason;
                break;

            case OP.PUSH_BYTES_1: .. case OP.PUSH_BYTES_64:
                const payload_size = opcode;  // encoded in the opcode
                if (bytes.length < payload_size)
                    assert(0);  // should have been validated

                const payload = bytes[0 .. payload_size];
                if (!stack.canPush(payload))
                    return "Stack overflow while executing PUSH_BYTES_*";

                stack.push(payload);
                bytes.popFrontN(payload.length);
                break;

            case OP.DUP:
                if (stack.empty)
                    return "DUP opcode requires an item on the stack";

                const top = stack.peek();
                if (!stack.canPush(top))
                    return "Stack overflow while executing DUP";
                stack.push(top);
                break;

            case OP.HASH:
                if (stack.empty)
                    return "HASH opcode requires an item on the stack";

                const top = stack.pop();
                const Hash hash = hashFull(top);
                if (!stack.canPush(hash[]))  // e.g. hash(1 byte) => 64 bytes
                    return "Stack overflow while executing HASH";
                stack.push(hash[]);
                break;

            case OP.CHECK_EQUAL:
                if (stack.count() < 2)
                    return "CHECK_EQUAL opcode requires two items on the stack";

                const a = stack.pop();
                const b = stack.pop();
                stack.push(a == b ? TRUE : FALSE);  // canPush() check unnecessary
                break;

            case OP.VERIFY_EQUAL:
                if (stack.count() < 2)
                    return "VERIFY_EQUAL opcode requires two items on the stack";

                const a = stack.pop();
                const b = stack.pop();
                if (a != b)
                    return "VERIFY_EQUAL operation failed";
                break;

            case OP.CHECK_SIG:
                // if changed, check assumptions
                static assert(Point.sizeof == 32);
                static assert(Signature.sizeof == 64);

                if (stack.count() < 2)
                    return "CHECK_SIG opcode requires two items on the stack";

                const key_bytes = stack.pop();
                if (key_bytes.length != Point.sizeof)
                    return "CHECK_SIG opcode requires 32-byte public key on the stack";
                if (!isValidPointBytes(key_bytes))
                    return "CHECK_SIG 32-byte public key on the stack is invalid";

                const sig_bytes = stack.pop();
                if (sig_bytes.length != Signature.sizeof)
                    return "CHECK_SIG opcode requires 64-byte signature on the stack";

                const point = Point(key_bytes);
                const sig = Signature(sig_bytes);
                if (Schnorr.verify(point, sig, tx))
                    stack.push(TRUE);  // canPush() check unnecessary
                else
                    stack.push(FALSE);
                break;

            default:
                break;
            }
        }

        if (!sc.empty())
            return "IF requires a closing END_IF";

        return null;
    }

    private static string handleConditional (in OP opcode,
        ref Stack stack, ref ScopeCondition sc)
    {
        switch (opcode)
        {
        case OP.IF:
        case OP.NOT_IF:
            if (!sc.isTrue())
            {
                sc.push(false);  // enter new scope, remain false
                break;
            }

            if (stack.count() < 1)
                return "IF/NOT_IF opcode requires an item on the stack";

            const top = stack.pop();
            if (top != TRUE && top != FALSE)
                return "IF/NOT_IF may only be used with OP.TRUE / OP.FALSE values";

            sc.push((opcode == OP.IF) ^ (top == FALSE));
            break;

        case OP.ELSE:
            if (sc.empty())
                return "Cannot have an ELSE without an associated IF";
            sc.tryToggle();
            break;

        case OP.END_IF:
            if (sc.empty())
                return "Cannot have an END_IF without an associated IF";
            sc.pop();
            break;

        default:
            assert(0);
        }

        return null;
    }

    // Create the associated lock script
    private static string toLockScript (const(ubyte)[] bytes, out Script lock)
    {
        static assert(Hash.sizeof == 64);  // assumed size
        if (bytes.length == 0)
            return "Lock cannot be empty";

        // simple pay to public key hash
        if (bytes.length == Hash.sizeof)
        {
            const Hash hash = Hash(bytes);
            lock = createLockP2PKH(hash);
            return null;
        }

        // pay to script hash, or direct lock script
        LockType lock_type;
        if (!toLockType(bytes[0], lock_type))
            return "Unrecognized lock type";
        bytes.popFront();

        final switch (lock_type)
        {
            case LockType.Hash:
                if (bytes.length != Hash.sizeof)
                    return "LockType.Hash requires 64-byte hash argument";

                const Hash hash = Hash(bytes);
                lock = createLockP2SH(hash);
                break;

            case LockType.Script:
                if (bytes.length == 0)
                    return "LockType.Script requires at least one opcode";
                lock = Script(bytes);
                break;
        }

        return null;
    }

    private static bool hasStackFailed (/*in*/ ref Stack stack)  // peek() is not const
        pure nothrow @safe @nogc
    {
        return stack.empty() || stack.peek() != TRUE;
    }

    /***************************************************************************

        Reads the length and payload of the associated `PUSH_DATA_*` opcode,
        tries to push the payload onto the stack, and if successfull it advances
        the `opcodes` array to the next opcode.

        Pushing may fail if:
        - The item size exceeds the limits
        - Pushing the item to the stack would exceed the stack limits

        Params:
            OP = the associated `PUSH_DATA_*` opcode
            stack = the stack to push the payload to
            opcodes = the opcode / data byte array

        Returns:
            null if the stack push was successfull,
            otherwise the string explaining why it failed

    ***************************************************************************/

    private static string pushToStack (OP op)(ref Stack stack,
        ref const(ubyte)[] opcodes) nothrow @safe /*@nogc*/
    {
        static assert(op == OP.PUSH_DATA_1 || op == OP.PUSH_DATA_2);
        alias T = Select!(op == OP.PUSH_DATA_1, ubyte, ushort);
        if (opcodes.length < T.sizeof)
            assert(0);  // script should have been validated

        const T size = littleEndianToNative!T(opcodes[0 .. T.sizeof]);
        if (size == 0 || size > MAX_STACK_ITEM_SIZE)
            assert(0);  // ditto

        opcodes.popFrontN(T.sizeof);
        if (opcodes.length < size)
            assert(0);  // ditto

        const payload = opcodes[0 .. size];
        if (!stack.canPush(payload))
        {
            import std.conv : to;
            static immutable err = op.to!string ~ " opcode payload "
                ~ "exceeds item size or stack size limits";
            return err;
        }

        stack.push(payload);  // push to stack
        opcodes.popFrontN(size);  // advance to next opcode
        return null;
    }
}

/// See #1279
private bool isValidPointBytes (in ubyte[] bytes) /*pure*/ nothrow @trusted @nogc
{
    import libsodium.crypto_core_ed25519;
    return crypto_core_ed25519_is_valid_point(bytes.ptr) == 1;
}

///
unittest
{
    ubyte[32] data;
    assert(!isValidPointBytes(data));
}

// OP.TRUE / OP.FALSE
unittest
{
    // todo: these need elaborate tests later
}

// OP.DUP
unittest
{
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script, Script([OP.DUP]), Script.init),
        "DUP opcode requires an item on the stack");
}

// OP.HASH
unittest
{
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script, Script([OP.HASH]), Script.init),
        "HASH opcode requires an item on the stack");
}

// OP.CHECK_EQUAL
unittest
{
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script,
        Script([OP.CHECK_EQUAL]), Script.init),
        "CHECK_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 1, OP.CHECK_EQUAL]), Script.init),
        "CHECK_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 1, OP.PUSH_BYTES_1, 1, OP.CHECK_EQUAL]),
        Script.init),
        null);
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 2, OP.PUSH_BYTES_1, 1, OP.CHECK_EQUAL]),
        Script.init),
        "Script failed");
}

// OP.VERIFY_EQUAL
unittest
{
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script,
        Script([OP.VERIFY_EQUAL]), Script.init),
        "VERIFY_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 1, OP.VERIFY_EQUAL]), Script.init),
        "VERIFY_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(LockType.Script,   // OP.TRUE needed as VERIFY does not push to stack
        Script([OP.PUSH_BYTES_1, 1, OP.PUSH_BYTES_1, 1, OP.VERIFY_EQUAL, OP.TRUE]),
        Script.init),
        null);
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 2, OP.PUSH_BYTES_1, 1, OP.VERIFY_EQUAL, OP.TRUE]),
        Script.init),
        "VERIFY_EQUAL operation failed");
}

// OP.CHECK_SIG
unittest
{
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script,
        Script([OP.CHECK_SIG]), Script.init),
        "CHECK_SIG opcode requires two items on the stack");
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 1, OP.CHECK_SIG]), Script.init),
        "CHECK_SIG opcode requires two items on the stack");
    test!("==")(engine.execute(LockType.Script,
        Script([OP.PUSH_BYTES_1, 1, OP.PUSH_BYTES_1, 1, OP.CHECK_SIG]),
        Script.init),
        "CHECK_SIG opcode requires 32-byte public key on the stack");

    // invalid key (crypto_core_ed25519_is_valid_point() fails)
    Point invalid_key;
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(OP.PUSH_BYTES_1), ubyte(1)]
            ~ [ubyte(32)] ~ invalid_key[]
            ~ [ubyte(OP.CHECK_SIG)]), Script.init),
        "CHECK_SIG 32-byte public key on the stack is invalid");

    Point valid_key = Point.fromString(
        "0x44404b654d6ddf71e2446eada6acd1f462348b1b17272ff8f36dda3248e08c81");
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(OP.PUSH_BYTES_1), ubyte(1)]
            ~ [ubyte(32)] ~ valid_key[]
            ~ [ubyte(OP.CHECK_SIG)]), Script.init),
        "CHECK_SIG opcode requires 64-byte signature on the stack");

    Signature invalid_sig;
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(OP.PUSH_BYTES_64)] ~ invalid_sig[]
            ~ [ubyte(32)] ~ valid_key[]
            ~ [ubyte(OP.CHECK_SIG)]), Script.init),
        "Script failed");
}

// P2PKH. There is no special code flow, executed as normal unlock + lock
unittest
{
    Pair kp = Pair.random();
    Transaction tx;
    auto sig = sign(kp, tx);

    const key_hash = hashFull(kp.V);
    Script lock = createLockP2PKH(key_hash);
    assert(lock.isValidSyntax());

    Script unlock = createUnlockP2PKH(sig, kp.V);
    assert(unlock.isValidSyntax());

    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script, lock, unlock, tx), null);

    Script bad_key_unlock = createUnlockP2PKH(sig, Pair.random.V);
    test!("==")(engine.execute(LockType.Script, lock, bad_key_unlock, tx),
        "VERIFY_EQUAL operation failed");
}

// P2SH. Special code flow.
unittest
{
    Pair kp = Pair.random();
    Transaction tx;
    auto sig = sign(kp, tx);

    Script redeem = Script([ubyte(32)] ~ kp.V[] ~ [ubyte(OP.CHECK_SIG)]);
    const redeem_hash = hashFull(redeem);

    const key_hash = hashFull(kp.V);
    Script lock = createLockP2SH(redeem_hash);
    assert(lock.isValidSyntax());

    Script unlock = createUnlockP2SH(sig, redeem);
    assert(unlock.isValidSyntax());

    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script, lock, unlock, tx), null);

    Script wrong_redeem = Script([ubyte(32)] ~ Pair.random.V[]
        ~ [ubyte(OP.CHECK_SIG)]);

    // bad redeem script
    Script bad_redeem_unlock = createUnlockP2SH(sig, wrong_redeem);
    assert(bad_redeem_unlock.isValidSyntax());
    test!("==")(engine.execute(LockType.Script, lock, bad_redeem_unlock, tx), "Script failed");

    // good redeem script but bad signature
    auto wrong_sig = sign(kp, "bad");
    Script bad_sig_unlock = createUnlockP2SH(wrong_sig, redeem);
    assert(bad_sig_unlock.isValidSyntax());
    test!("==")(engine.execute(LockType.Script, lock, bad_sig_unlock, tx), "Script failed");
}

// Basic invalid script verification
unittest
{
    Pair kp = Pair.random();
    Transaction tx;
    auto sig = sign(kp, tx);

    const key_hash = hashFull(kp.V);
    Script lock = createLockP2PKH(key_hash);
    assert(lock.isValidSyntax());

    Script unlock = createUnlockP2PKH(sig, kp.V);
    assert(unlock.isValidSyntax());

    const invalid_script = Script([255]);
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script, lock, unlock, tx), null);
    // invalid scripts / sigs
    test!("==")(engine.execute(LockType.Script, invalid_script, unlock, tx),
        "Lock script error: Script contains an unrecognized opcode");
    test!("==")(engine.execute(LockType.Script, lock, invalid_script, tx),
        "Unlock script error: Script contains an unrecognized opcode");
}

// Item size & stack size limits checks
unittest
{
    import std.algorithm;
    scope engine = new Engine();
    test!("==")(engine.execute(LockType.Script,
        Script([42].toPushData() ~ [ubyte(OP.TRUE)]),
        Script.init),
        null);

    test!("==")(engine.execute(LockType.Script,
        Script(ubyte(42).repeat(MAX_STACK_ITEM_SIZE + 1).array.toPushData()
        ~ [ubyte(OP.TRUE)]),
        Script.init),
        "Lock script error: PUSH_DATA_2 opcode requires payload size value to be between 1 and 512");

    const MaxItemPush = ubyte(42).repeat(MAX_STACK_ITEM_SIZE).array.toPushData();
    const MaxPushes = MAX_STACK_TOTAL_SIZE / MAX_STACK_ITEM_SIZE;
    // test will have to be made more flexible in the future,
    // currently assuming both limits are a power of 2.
    assert(MAX_STACK_TOTAL_SIZE % MAX_STACK_ITEM_SIZE == 0);

    // strictly above limit
    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes + 1).joiner.array ~ [ubyte(OP.TRUE)]),
        Script.init),
        "PUSH_DATA_2 opcode payload exceeds item size or stack size limits");

    // within limit, but missing OP.TRUE on stack
    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array),
        Script.init),
        "Script failed");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array ~ [ubyte(OP.TRUE)]),
        Script.init),
        "Stack overflow while pushing OP.TRUE");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array ~ [ubyte(OP.FALSE)]),
        Script.init),
        "Stack overflow while pushing OP.FALSE");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(1)].toPushData()),
        Script.init),
        "PUSH_DATA_1 opcode payload exceeds item size or stack size limits");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(1), ubyte(1)]),
        Script.init),
        "Stack overflow while executing PUSH_BYTES_*");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(OP.DUP)]),
        Script.init),
        "Stack overflow while executing DUP");

    // will fit, pops MAX_STACK_ITEM_SIZE and pushes 64 bytes
    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(OP.HASH), ubyte(OP.TRUE)]),
        Script.init),
        null);

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes - 1).joiner.array
        ~ [ubyte(1), ubyte(1)].repeat(MAX_STACK_ITEM_SIZE).joiner.array
        ~ ubyte(OP.HASH) ~ [ubyte(OP.TRUE)]),
        Script.init),
        "Stack overflow while executing HASH");
}

// IF, NOT_IF, ELSE, END_IF conditional logic
unittest
{
    scope engine = new Engine();

    /* simple conditionals */

    // IF true => execute if branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.TRUE, OP.IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Script.init),
        null);

    // IF false => execute else branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.FALSE, OP.IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Script.init),
        "Script failed");

    // NOT_IF true => execute if branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.FALSE, OP.NOT_IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Script.init),
        null);

    // NOT_IF false => execute else branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.TRUE, OP.NOT_IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Script.init),
        "Script failed");

    /* nested conditionals */

    // IF true => IF true => 3
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(1), ubyte(3), OP.CHECK_EQUAL]),
        Script([OP.TRUE, OP.IF,
                           OP.TRUE, OP.IF,
                                      ubyte(1), ubyte(3),
                                    OP.ELSE,
                                      ubyte(1), ubyte(4),
                                    OP.END_IF,
                         OP.ELSE,
                           OP.TRUE, OP.IF,
                                      ubyte(1), ubyte(5),
                                    OP.ELSE,
                                      ubyte(1), ubyte(6),
                                    OP.END_IF,
                         OP.END_IF])),
        null);

    // IF true => NOT_IF false => 4
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(1), ubyte(4), OP.CHECK_EQUAL]),
        Script([OP.TRUE, OP.IF,
                           OP.TRUE, OP.NOT_IF,
                                      ubyte(1), ubyte(3),
                                    OP.ELSE,
                                      ubyte(1), ubyte(4),
                                    OP.END_IF,
                         OP.ELSE,
                           OP.TRUE, OP.IF,
                                      ubyte(1), ubyte(5),
                                    OP.ELSE,
                                      ubyte(1), ubyte(6),
                                    OP.END_IF,
                         OP.END_IF])),
        null);

    // IF false => IF true => 5
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(1), ubyte(5), OP.CHECK_EQUAL]),
        Script([OP.FALSE, OP.IF,
                            OP.TRUE, OP.IF,
                                       ubyte(1), ubyte(3),
                                     OP.ELSE,
                                       ubyte(1), ubyte(4),
                                     OP.END_IF,
                          OP.ELSE,
                            OP.TRUE, OP.IF,
                                       ubyte(1), ubyte(5),
                                     OP.ELSE,
                                       ubyte(1), ubyte(6),
                                     OP.END_IF,
                          OP.END_IF])),
        null);

    // IF false => NOT_IF FALSE => 6
    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(1), ubyte(6), OP.CHECK_EQUAL]),
        Script([OP.FALSE, OP.IF,
                            OP.TRUE, OP.IF,
                                       ubyte(1), ubyte(3),
                                     OP.ELSE,
                                       ubyte(1), ubyte(4),
                                     OP.END_IF,
                          OP.ELSE,
                            OP.TRUE, OP.NOT_IF,
                                       ubyte(1), ubyte(5),
                                     OP.ELSE,
                                       ubyte(1), ubyte(6),
                                     OP.END_IF,
                          OP.END_IF])),
        null);

    /* syntax checks */
    test!("==")(engine.execute(LockType.Script,
        Script([OP.IF]),
        Script.init),
        "IF/NOT_IF opcode requires an item on the stack");

    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(1), ubyte(2), OP.IF]),
        Script.init),
        "IF/NOT_IF may only be used with OP.TRUE / OP.FALSE values");

    test!("==")(engine.execute(LockType.Script,
        Script([OP.TRUE, OP.IF]),
        Script.init),
        "IF requires a closing END_IF");
}
