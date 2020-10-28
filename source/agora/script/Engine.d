/*******************************************************************************

    Contains the script execution engine (non-webASM)

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

/// Contains the Lock, which is a tag and either a Hash or set of opcodes
public struct Lock
{
    /// Specifies the type of lock script
    public LockType type;

    /// May either be a Hash, or a sequence of opcodes
    public const(ubyte)[] bytes;
}

/// Contains the Unlock, which can be a data tuple or a set of push opcodes
public struct Unlock
{
    /// May be: <signature>, <signature, key>, <push opcodes>
    public const(ubyte)[] bytes;
}

/// The engine executes scripts, and returns a value or throws
public class Engine
{
    /// Conditional opcodes require the top item on the stack to be one of these
    private static immutable ubyte[1] TRUE = [OP.TRUE];
    /// Ditto
    private static immutable ubyte[1] FALSE = [OP.FALSE];

    /// historic backwards compatibility for the tests.
    /// The tests were originally written following Bitcoin script layout,
    /// but was later replaced with a lock type tag (see toLock script()).
    //version (unittest)
    //private string execute (in Script lock_script, in Script unlock)
    //{
    //    Transaction tx;
    //    Lock lock = { LockType.Script, lock_script[] };
    //    return this.execute(lock, unlock[], tx);
    //}

    ///// ditto
    //version (unittest)
    //private string execute (Lock lock, in Script unlock, in Transaction tx)
    //{
    //    return this.execute(lock, Unlock(unlock[]), tx);
    //}

    /***************************************************************************

        Main dispatch execution routine.

        The lock type will be examined, and based on its type execution will
        proceed to either simple script-less payments, or script-based payments.

        Params:
            lock = the lock
            unlock = may contain a <signature>, <signature, key>,
                           or <script> which only contains stack push opcodes

        Returns:
            null if there were no errors,
            or a string explaining the reason execution failed

    ***************************************************************************/

    public string execute (Lock lock, Unlock unlock, in Transaction tx)
    {
        if (lock.bytes.length == 0)
            return "Lock cannot be empty";

        final switch (lock.type)
        {
            case LockType.Key:
            case LockType.KeyHash:
                if (auto error = handleBasicPayment(lock, unlock, tx))
                    return error;

                break;

            case LockType.Script:
                if (auto error = executeBasicScripts(lock, unlock, tx))
                    return error;

                break;

            case LockType.ScriptHash:
                if (auto error = executeScriptHash(lock, unlock, tx))
                    return error;

                break;
        }

        return null;
    }

    /***************************************************************************

        Handle stack-less and script-less basic payments.

        If the lock is a P2K, the unlock must only contain a <signature>.
        If the lock is a P2KH, the unlock must contain a <signature, key>.

        Params:
            lock = must contain a <pubkey> or a <hash>
            unlock = must contain a <signature> or <signature, key>

        Returns:
            null if there were no errors,
            or a string explaining the reason execution failed

    ***************************************************************************/

    private static string handleBasicPayment (in Lock lock, in Unlock unlock,
        in Transaction tx)
    {
        // assumed sizes
        static assert(Point.sizeof == 32);
        static assert(Hash.sizeof == 64);

        switch (lock.type)
        {
        case LockType.Key:
            if (lock.bytes.length != Point.sizeof)
                return "Lock script: LockType.Key requires 32-byte key argument";
            if (!isValidPointBytes(lock.bytes))
                return "Lock script: LockType.Key 32-byte public key in lock script is invalid";
            const Point key = Point(lock.bytes);

            if (unlock.bytes.length != Signature.sizeof)
                return "Lock script: LockType.Key requires a 64-byte signature in the Unlock script";
            const sig = Signature(unlock.bytes);
            if (!Schnorr.verify(key, sig, tx))
                return "Unlock script: LockType.Key signature failed validation";

            break;

        case LockType.KeyHash:
            if (lock.bytes.length != Hash.sizeof)
                return "Lock script: LockType.KeyHash requires 64-byte key hash argument";
            const Hash key_hash = Hash(lock.bytes);

            const(ubyte)[] bytes = unlock.bytes;
            if (bytes.length != Signature.sizeof + Point.sizeof)
                return "Unlock script: LockType.KeyHash requires a 64-byte "
                     ~ "signature and 32-byte key in the Unlock script";
            const sig = Signature(bytes[0 .. Signature.sizeof]);
            bytes.popFrontN(Signature.sizeof);

            if (!isValidPointBytes(bytes))
                return "Unlock script: LockType.KeyHash 32-byte public key in lock script is invalid";
            const Point key = Point(bytes);

            if (!Schnorr.verify(key, sig, tx))
                return "Unlock script: LockType.KeyHash signature failed validation";

            break;

        default:
            assert(0);
        }

        return null;
    }

    /***************************************************************************

        Execute a LockType.Script type of lock script.

        The unlock script may only contain stack pushes.
        The unlock script is ran, producing a stack.

        Thereafter, the lock script will run with the stack
        of the unlock script.

        Params:
            lock = the lock script
            unlock = the unlock script
            tx = the spending transaction

        Returns:
            null if there were no errors,
            or a string explaining the reason execution failed

    ***************************************************************************/

    private static string executeBasicScripts (in Lock lock,
        in Unlock unlock, in Transaction tx)
    {
        assert(lock.type == LockType.Script);

        Script unlock_script = Script(unlock.bytes);
        if (auto error = unlock_script.isInvalidSyntaxReason(ScriptType.Unlock))
            return error;

        Script lock_script = Script(lock.bytes);
        if (auto error = lock_script.isInvalidSyntaxReason(ScriptType.Lock))
            return error;

        Stack stack;
        if (auto error = executeScript(unlock_script, stack, tx))
            return error;

        if (auto error = executeScript(lock_script, stack, tx))
            return error;

        if (hasStackFailed(stack))
            return "Script failed";

        return null;
    }

    /***************************************************************************

        Execute a P2SH (Pay 2 Script Hash) type of lock script.

        The 64-byte hash of the redeem script `H` is read from `lock_bytes`,
        `unlock_bytes` is evaluated as a set of pushes to the stack where
        the last push is the redeem script. The redeem script is popped from the
        stack, hashed, and compared to `H` from the lock script. Then it's
        evaluated with any leftover stack items.

        Params:
            lock = must contain a 64-byte hash of the redeem script
            unlock = must contain only stack push opcodes, where the last
                           push is the redeem script itself
            tx = the associated spending transaction

        Returns:
            null if there were no errors,
            or a string explaining the reason execution failed

    ***************************************************************************/

    private static string executeScriptHash (Lock lock, Unlock unlock,
        in Transaction tx)
    {
        assert(lock.type == LockType.ScriptHash);

        if (lock.bytes.length != Hash.sizeof)
            return "Lock script: LockType.ScriptHash requires 64-byte script hash argument";
        const Hash script_hash = Hash(lock.bytes);

        Script unlock_script = Script(unlock.bytes);
        if (auto error = unlock_script.isInvalidSyntaxReason(ScriptType.Unlock))
            return error;

        Stack stack;
        if (auto error = executeScript(unlock_script, stack, tx))
            return error;

        if (stack.empty())
            return "Unlock script did not push a redeem script to the stack";

        const redeem_bytes = stack.pop();
        if (hashFull(redeem_bytes) != script_hash)
            return "Hash of Unlock script does not match script hash argument in Lock script";

        Script redeem = Script(redeem_bytes);
        if (auto error = redeem.isInvalidSyntaxReason(ScriptType.Redeem))
            return error;

        if (auto error = executeScript(redeem, stack, tx))
            return error;

        if (hasStackFailed(stack))
            return "Script failed";

        return null;
    }

    /***************************************************************************

        Execute the script with the given stack and the associated transaction

        Params:
            script = the script to execute
            stack = the stack to use for the script. May be non-empty.
            tx = the associated spending transaction

        Returns:
            null if there were no errors,
            or a string explaining the reason execution failed

    ***************************************************************************/

    private static string executeScript (in Script script, ref Stack stack,
        in Transaction tx)
    {
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

    /***************************************************************************

        Handle a conditional opcode

        Params:
            opcode = the current conditional
            stack = the stack to evaluate for the conditional
            sc = the scope condition which may be toggled

        Returns:
            null if there were no errors,
            or a string explaining the reason execution failed

    ***************************************************************************/

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

    /***************************************************************************

        Checks if the stack has a failing condition.
        The stack may only be evaluated as true when it has a single
        OP.TRUE item on the stack.

        Params:
            stack = the stack to check

        Returns:
            true if the stack has failed

    ***************************************************************************/

    private static bool hasStackFailed (/*in*/ ref Stack stack) // peek() is not const
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
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.DUP]), Unlock.init, Transaction.init),
        "DUP opcode requires an item on the stack");
}

// OP.HASH
unittest
{
    scope engine = new Engine();
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.HASH]), Unlock.init, Transaction.init),
        "HASH opcode requires an item on the stack");
}

// OP.CHECK_EQUAL
unittest
{
    scope engine = new Engine();
    const Transaction tx;
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.CHECK_EQUAL]), Unlock.init, tx),
        "CHECK_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 1, OP.CHECK_EQUAL]),
        Unlock.init, tx),
        "CHECK_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 1, OP.PUSH_BYTES_1, 1, OP.CHECK_EQUAL]),
        Unlock.init, tx),
        null);
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 2, OP.PUSH_BYTES_1, 1, OP.CHECK_EQUAL]),
        Unlock.init, tx),
        "Script failed");
}

// OP.VERIFY_EQUAL
unittest
{
    scope engine = new Engine();
    const Transaction tx;
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.VERIFY_EQUAL]), Unlock.init, tx),
        "VERIFY_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 1, OP.VERIFY_EQUAL]),
        Unlock.init, tx),
        "VERIFY_EQUAL opcode requires two items on the stack");
    test!("==")(engine.execute(   // OP.TRUE needed as VERIFY does not push to stack
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 1, OP.PUSH_BYTES_1, 1, OP.VERIFY_EQUAL, OP.TRUE]),
        Unlock.init, tx),
        null);
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 2, OP.PUSH_BYTES_1, 1, OP.VERIFY_EQUAL, OP.TRUE]),
        Unlock.init, tx),
        "VERIFY_EQUAL operation failed");
}

// OP.CHECK_SIG
unittest
{
    scope engine = new Engine();
    const Transaction tx;
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.CHECK_SIG]), Unlock.init, tx),
        "CHECK_SIG opcode requires two items on the stack");
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 1, OP.CHECK_SIG]),
        Unlock.init, tx),
        "CHECK_SIG opcode requires two items on the stack");
    test!("==")(engine.execute(
        Lock(LockType.Script, [OP.PUSH_BYTES_1, 1, OP.PUSH_BYTES_1, 1, OP.CHECK_SIG]),
        Unlock.init, tx),
        "CHECK_SIG opcode requires 32-byte public key on the stack");

    // invalid key (crypto_core_ed25519_is_valid_point() fails)
    Point invalid_key;
    test!("==")(engine.execute(
        Lock(LockType.Script, [ubyte(OP.PUSH_BYTES_1), ubyte(1)]
            ~ [ubyte(32)] ~ invalid_key[]
            ~ [ubyte(OP.CHECK_SIG)]), Unlock.init, tx),
        "CHECK_SIG 32-byte public key on the stack is invalid");

    Point valid_key = Point.fromString(
        "0x44404b654d6ddf71e2446eada6acd1f462348b1b17272ff8f36dda3248e08c81");
    test!("==")(engine.execute(
        Lock(LockType.Script, [ubyte(OP.PUSH_BYTES_1), ubyte(1)]
            ~ [ubyte(32)] ~ valid_key[]
            ~ [ubyte(OP.CHECK_SIG)]), Unlock.init, tx),
        "CHECK_SIG opcode requires 64-byte signature on the stack");

    Signature invalid_sig;
    test!("==")(engine.execute(
        Lock(LockType.Script, [ubyte(OP.PUSH_BYTES_64)] ~ invalid_sig[]
            ~ [ubyte(32)] ~ valid_key[]
            ~ [ubyte(OP.CHECK_SIG)]), Unlock.init, tx),
        "Script failed");
}

// Native P2PK (Pay to Public Key), consumes 33 bytes
unittest
{
    const Pair kp = Pair.random();
    const Transaction tx;
    const sig = sign(kp, tx);

    scope engine = new Engine();
    test!("==")(engine.execute(
        Lock(LockType.Key, kp.V[]), Unlock(sig[]), tx),
        null);

    const bad_sig = sign(kp, "foobar");
    test!("==")(engine.execute(
        Lock(LockType.Key, kp.V[]), Unlock(bad_sig[]), tx),
        "Unlock script: LockType.Key signature failed validation");

    const bad_key = Pair.random().V;
    test!("==")(engine.execute(
        Lock(LockType.Key, bad_key[]), Unlock(sig[]), tx),
        "Unlock script: LockType.Key signature failed validation");
}

// Native P2PKH (Pay to Public Key Hash), consumes 65 bytes
unittest
{
    const Pair kp = Pair.random();
    const key_hash = hashFull(kp.V);
    const Transaction tx;
    const sig = sign(kp, tx);

    scope engine = new Engine();
    test!("==")(engine.execute(
        Lock(LockType.KeyHash, key_hash[]), Unlock(sig[] ~ kp.V[]), tx),
        null);

    const bad_sig = sign(kp, "foo")[];
    test!("==")(engine.execute(
        Lock(LockType.KeyHash, key_hash[]), Unlock(bad_sig[] ~ kp.V[]), tx),
        "Unlock script: LockType.KeyHash signature failed validation");

    const bad_key = Pair.random().V;
    test!("==")(engine.execute(
        Lock(LockType.KeyHash, key_hash[]), Unlock(sig[] ~ bad_key[]), tx),
        "Unlock script: LockType.KeyHash signature failed validation");
}

// Native script, emulating bitcoin-style P2PKH
unittest
{
    const Pair kp = Pair.random();
    const Transaction tx;
    const sig = sign(kp, tx);

    const key_hash = hashFull(kp.V);
    const Script lock = createLockP2PKH(key_hash);
    const Script unlock = createUnlockP2PKH(sig, kp.V);

    scope engine = new Engine();
    test!("==")(engine.execute(
        Lock(LockType.Script, lock[]), Unlock(unlock[]), tx),
        null);

    Script bad_key_unlock = createUnlockP2PKH(sig, Pair.random.V);
    test!("==")(engine.execute(
        Lock(LockType.Script, lock[]), Unlock(bad_key_unlock[]), tx),
        "VERIFY_EQUAL operation failed");
}

// Basic invalid script verification
unittest
{
    Pair kp = Pair.random();
    Transaction tx;
    const sig = sign(kp, tx);

    const key_hash = hashFull(kp.V);
    Script lock = createLockP2PKH(key_hash);
    Script unlock = createUnlockP2PKH(sig, kp.V);

    const invalid_script = Script([255]);
    scope engine = new Engine();
    test!("==")(engine.execute(
        Lock(LockType.Script, lock[]), Unlock(unlock[]), tx),
        null);
    // invalid scripts / sigs
    test!("==")(engine.execute(
        Lock(LockType.Script, invalid_script[]), Unlock(unlock[]), tx),
        "Lock script error: Script contains an unrecognized opcode");
    test!("==")(engine.execute(
        Lock(LockType.Script, lock[]), Unlock(invalid_script[]), tx),
        "Unlock script error: Script contains an unrecognized opcode");
}

// Item size & stack size limits checks
unittest
{
    import std.algorithm;
    scope engine = new Engine();
    const Transaction tx;
    test!("==")(engine.execute(
        Lock(LockType.Script, [42].toPushData() ~ [ubyte(OP.TRUE)]),
        Unlock.init, tx),
        null);

    test!("==")(engine.execute(
        Lock(LockType.Script, ubyte(42).repeat(MAX_STACK_ITEM_SIZE + 1)
            .array.toPushData()
            ~ [ubyte(OP.TRUE)]),
        Unlock.init, tx),
        "Lock script error: PUSH_DATA_2 opcode requires payload size value to be between 1 and 512");

    const MaxItemPush = ubyte(42).repeat(MAX_STACK_ITEM_SIZE).array.toPushData();
    const MaxPushes = MAX_STACK_TOTAL_SIZE / MAX_STACK_ITEM_SIZE;
    // test will have to be made more flexible in the future,
    // currently assuming both limits are a power of 2.
    assert(MAX_STACK_TOTAL_SIZE % MAX_STACK_ITEM_SIZE == 0);

    // strictly above limit
    test!("==")(engine.execute(
        Lock(LockType.Script, MaxItemPush.repeat(MaxPushes + 1).joiner.array
            ~ [ubyte(OP.TRUE)]),
        Unlock.init, tx),
        "PUSH_DATA_2 opcode payload exceeds item size or stack size limits");

    // within limit, but missing OP.TRUE on stack
    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array),
        Unlock.init, tx),
        "Script failed");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array ~ [ubyte(OP.TRUE)]),
        Unlock.init, tx),
        "Stack overflow while pushing OP.TRUE");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array ~ [ubyte(OP.FALSE)]),
        Unlock.init, tx),
        "Stack overflow while pushing OP.FALSE");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(1)].toPushData()),
        Unlock.init, tx),
        "PUSH_DATA_1 opcode payload exceeds item size or stack size limits");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(1), ubyte(1)]),
        Unlock.init, tx),
        "Stack overflow while executing PUSH_BYTES_*");

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(OP.DUP)]),
        Unlock.init, tx),
        "Stack overflow while executing DUP");

    // will fit, pops MAX_STACK_ITEM_SIZE and pushes 64 bytes
    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes).joiner.array
        ~ [ubyte(OP.HASH), ubyte(OP.TRUE)]),
        Unlock.init, tx),
        null);

    test!("==")(engine.execute(LockType.Script,
        Script(MaxItemPush.repeat(MaxPushes - 1).joiner.array
        ~ [ubyte(1), ubyte(1)].repeat(MAX_STACK_ITEM_SIZE).joiner.array
        ~ ubyte(OP.HASH) ~ [ubyte(OP.TRUE)]),
        Unlock.init, tx),
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
        Unlock.init, tx),
        null);

    // IF false => execute else branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.FALSE, OP.IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Unlock.init, tx),
        "Script failed");

    // NOT_IF true => execute if branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.FALSE, OP.NOT_IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Unlock.init, tx),
        null);

    // NOT_IF false => execute else branch
    test!("==")(engine.execute(LockType.Script,
        Script([OP.TRUE, OP.NOT_IF, OP.TRUE, OP.ELSE, OP.FALSE, OP.END_IF]),
        Unlock.init, tx),
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
        Unlock.init, tx),
        "IF/NOT_IF opcode requires an item on the stack");

    test!("==")(engine.execute(LockType.Script,
        Script([ubyte(1), ubyte(2), OP.IF]),
        Unlock.init, tx),
        "IF/NOT_IF may only be used with OP.TRUE / OP.FALSE values");

    test!("==")(engine.execute(LockType.Script,
        Script([OP.TRUE, OP.IF]),
        Unlock.init, tx),
        "IF requires a closing END_IF");
}
