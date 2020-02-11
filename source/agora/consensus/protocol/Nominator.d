/*******************************************************************************

    Contains the SCP consensus driver implementation.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.protocol.Nominator;

import agora.common.crypto.Key;
import agora.common.Deserializer;
import agora.common.Hash : hashFull;
import agora.common.Serializer;
import agora.common.Set;
import agora.common.Task;
import agora.consensus.data.Block;
import agora.consensus.data.Transaction;
import agora.network.NetworkClient;
import agora.node.Ledger;
import agora.utils.Log;
import agora.utils.PrettyPrinter;

import scpd.Cpp;
import scpd.scp.SCP;
import scpd.scp.SCPDriver;
import scpd.scp.Slot;
import scpd.scp.Utils;
import scpd.types.Stellar_types;
import scpd.types.Stellar_types : StellarHash = Hash;
import scpd.types.Stellar_SCP;
import scpd.types.Utils;
import scpd.Util;

import std.algorithm;
import core.stdc.stdint;
import core.time;

mixin AddLogger!();

/// Ditto
public extern (C++) class Nominator : SCPDriver
{
    /// SCP instance
    private SCP* scp;

    /// Key pair of this node
    private KeyPair key_pair;

    /// Task manager
    private TaskManager taskman;

    /// Ledger instance
    private Ledger ledger;

    /// This node's quorum node clients
    private NetworkClient[PublicKey] peers;

    /// The set of externalized slot indices
    private Set!uint64_t externalized_slots;

    /// The quorum set
    private SCPQuorumSetPtr[StellarHash] quorum_set;

    /// Ballot / Nomination timers
    public Set!ulong[Slot.TimerType.max + 1] timers;

extern(D):

    /***************************************************************************

        Constructor

        Params:
            key_pair = the key pair of this node
            ledger = needed for SCP state restoration & block validation
            taskman = used to run timers
            peers = the set of clients to the peers in the quorum
            quorum_set = the quorum set of this node

    ***************************************************************************/

    public this (KeyPair key_pair, Ledger ledger,
        TaskManager taskman, NetworkClient[PublicKey] peers,
        SCPQuorumSet quorum_set)
    {
        import std.traits;
        // initialize so opIndex does not throw
        foreach (type; EnumMembers!(Slot.TimerType))
            this.timers[type] = Set!ulong.init;

        this.key_pair = key_pair;
        auto node_id = NodeID(StellarHash(key_pair.address[]));
        const IsValidator = true;
        this.scp = createSCP(this, node_id, IsValidator, quorum_set);
        this.taskman = taskman;
        this.ledger = ledger;
        this.peers = peers;

        // cast: see makeSharedSCPQuorumSet() in Cpp.d
        auto local_quorum_set = this.scp.getLocalQuorumSet();
        auto localQSet = makeSharedSCPQuorumSet(local_quorum_set);

        const bytes = ByteSlice.make(XDRToOpaque(*localQSet));
        auto quorum_hash = sha256(bytes);
        this.quorum_set[quorum_hash] = localQSet;

        this.restoreSCPState(ledger);
        this.ledger.setNominator(&this.nominateTransactionSet);
    }

    /***************************************************************************

        Nominate a new transaction set to the quorum.
        Failure to nominate is only logged.

        Params:
            slot_idx = the index of the slot to nominate for
            prev = the transaction set of the previous slot
            next = the proposed transaction set for the provided slot index

    ***************************************************************************/

    private void nominateTransactionSet (ulong slot_idx, Set!Transaction prev,
        Set!Transaction next) @trusted
    {
        log.info("{}(): Proposing tx set for slot {}", __FUNCTION__, slot_idx);

        auto prev_value = prev.serializeFull().toVec();
        auto next_value = next.serializeFull().toVec();
        if (this.scp.nominate(slot_idx, next_value, prev_value))
        {
            log.info("{}(): Tx set nominated", __FUNCTION__);
        }
        else
        {
            log.info("{}(): Tx set rejected nomination", __FUNCTION__);
        }
    }

    /***************************************************************************

        Restore SCP's internal state based on the provided ledger state

        Params:
            ledger = the ledger instance

    ***************************************************************************/

    private void restoreSCPState (Ledger ledger)
    {
        import agora.common.Serializer;
        import scpd.types.Stellar_SCP;
        import scpd.types.Utils;
        import scpd.types.Stellar_types : StellarHash = Hash, NodeID;
        import std.range;

        auto key = StellarHash(this.key_pair.address[]);
        auto pub_key = NodeID(key);

        foreach (block_idx, block; ledger.getBlocksFrom(0).enumerate)
        {
            Value block_value = block.serializeFull().toVec();

            SCPStatement statement =
            {
                nodeID: pub_key,
                slotIndex: block_idx,
                pledges: {
                    type_: SCPStatementType.SCP_ST_EXTERNALIZE,
                    externalize_: {
                        commit: {
                            counter: 0,
                            value: block_value,
                        },
                        nH: 0,
                    },
                },
            };

            SCPEnvelope env = SCPEnvelope(statement);
            this.scp.setStateFromEnvelope(block_idx, env);
            if (!this.scp.isSlotFullyValidated(block_idx))
                assert(0);
        }

        // there should at least be a genesis block
        if (this.scp.empty())
            assert(0);
    }

    /***************************************************************************

        Called when a new SCP Envelope is received from the network.

        Params:
            envelope = the SCP envelope

        Returns:
            true if the SCP protocol accepted this envelope

    ***************************************************************************/

    public bool receiveEnvelope (SCPEnvelope envelope) @trusted
    {
        return this.scp.receiveEnvelope(envelope) == SCP.EnvelopeState.VALID;
    }

    extern (C++):


    /***************************************************************************

        Signs the SCPEnvelope with the node's private key.

        todo: Currently not signing yet. To be done.

        Params:
            envelope = the SCPEnvelope to sign

    ***************************************************************************/

    public override void signEnvelope (ref SCPEnvelope envelope)
    {
    }

    /***************************************************************************

        Validates the provided transaction set for the provided slot index,
        and returns a status code of the validation.

        Params:
            slot_idx = the slot index we're currently reaching consensus for
            value = the transaction set to validate
            nomination = unused, seems to be stellar-specific

    ***************************************************************************/

    public override ValidationLevel validateValue (uint64_t slot_idx,
        ref const(Value) value, bool nomination) nothrow
    {
        scope (failure) assert(0);

        try
        {
            auto tx_set = deserializeFull!(Set!Transaction)(
                cast(ubyte[])value[]);

            if (auto fail_reason = this.ledger.validateTxSet(tx_set))
            {
                log.error("validateValue(): Invalid tx set: {}", fail_reason);
                return ValidationLevel.kInvalidValue;
            }
        }
        catch (Exception ex)
        {
            log.error("{}: Received invalid tx set. Error: {}",
                __FUNCTION__, ex.message);

            return ValidationLevel.kInvalidValue;
        }

        return ValidationLevel.kFullyValidatedValue;
    }

    /***************************************************************************

        Called when consenus has been reached for the provided slot index and
        the transaction set.

        Params:
            slot_idx = the slot index
            value = the transaction set

    ***************************************************************************/

    public override void valueExternalized (uint64_t slot_idx,
        ref const(Value) value)
    {
        scope (failure) assert(0);

        if (slot_idx in this.externalized_slots)
            return;  // slot was already externalized
        this.externalized_slots.put(slot_idx);
        this.removeOutdatedTimers(slot_idx);

        auto bytes = cast(ubyte[])value[];
        auto tx_set = deserializeFull!(Set!Transaction)(bytes);

        if (tx_set.length == 0)
            assert(0, "Transaction set empty");

        log.info("Externalized transaction set at {}: {}", slot_idx, tx_set);
        if (!this.ledger.onTXSetExternalized(tx_set))
            assert(0);
    }

    /***************************************************************************

        Removes outdated timers after a slot has been externalized.

        Params:
            slot_idx = timers with a lower or equal ID will be removed

    ***************************************************************************/

    private void removeOutdatedTimers (uint64_t slot_idx) nothrow @trusted
    {
        scope (failure) assert(0);  // Set.opApply is not nothrow
        static ulong[] to_remove;
        foreach (type, timers; this.timers)
        foreach (timer_idx; timers)
        {
            if (timer_idx <= slot_idx)
                to_remove ~= timer_idx;
        }

        foreach (type, ref timers; this.timers)
            to_remove.each!(idx => timers.remove(idx));
    }

    /***************************************************************************

        Params:
            qSetHash = the hash of the quorum set

        Returns:
            the SCPQuorumSet pointer for the provided quorum set hash

    ***************************************************************************/

    public override SCPQuorumSetPtr getQSet (ref const(StellarHash) qSetHash)
    {
        if (auto scp_quroum = qSetHash in this.quorum_set)
            return *scp_quroum;

        return SCPQuorumSetPtr.init;
    }

    /***************************************************************************

        Floods the given SCPEnvelope to the network of connected peers.

        Params:
            envelope = the SCPEnvelope to flood to the network.

    ***************************************************************************/

    public override void emitEnvelope (ref const(SCPEnvelope) envelope)
    {
        try
        {
            foreach (key, node; this.peers)
            {
                // note: cannot deal with const parameter types in the API
                auto env = cast()envelope;

                // note: several error-cases not considered here yet:
                // A) request failure after N attepts => we might have to retry,
                // but exactly how much time do we have before the next round??
                // B) Node rejects the envelope. Possible in circular scenarios,
                // e.g. A => B => C => A (A rejects the envelope because it sent it first)
                node.sendEnvelope(env);
            }
        }
        catch (Exception ex)
        {
            import std.conv;
            assert(0, ex.to!string);
        }
    }

    /***************************************************************************

        Combine a set of transaction sets into a single transaction set.
        This may be done in arbitrary ways, as long as it's consistent
        (for a given input, the combined output is predictable).

        For simplicity we currently only pick the first transaction set
        to become the "combined" transaction set.

        Params:
            slot_idx = the slot index we're currently reaching consensus for
            candidates = a set of a set of transactions

    ***************************************************************************/

    public override Value combineCandidates (uint64_t slot_idx,
        ref const(set!Value) candidates)
    {
        scope (failure) assert(0);

        foreach (ref const(Value) candidate; candidates)
        {
            auto tx_set = deserializeFull!(Set!Transaction)(
                cast(ubyte[])candidate[]);

            if (auto msg = this.ledger.validateTxSet(tx_set))
            {
                log.error("combineCandidates(): Invalid tx set: {}", msg);
                continue;
            }
            else
            {
                log.info("combineCandidates: {}", slot_idx);
            }

            // todo: currently we just pick the first of the candidate values,
            // but we should ideally pick tx's out of the combined set
            return tx_set.serializeFull().toVec();
        }

        assert(0);  // should not reach here
    }

    public override void setupTimer (ulong slot_idx, int type,
        milliseconds timeout, CPPDelegate!(void function())* callback)
    {
        scope (failure) assert(0);

        assert(type >= Slot.TimerType.min && type <= Slot.TimerType.max);
        const timer_type = cast(Slot.TimerType)type;

        if (slot_idx <= this.ledger.getBlockHeight())
        {
            // remove all timers for this outdated externalized slot
            foreach (_, ref timers; this.timers)
                timers.remove(slot_idx);
            return;
        }

        if (timeout == 0)
        {
            // disable the timer for this type and slot
            this.timers[timer_type].remove(slot_idx);
            return;
        }

        this.timers[timer_type].put(slot_idx);
        this.taskman.runTask(
        {
            this.taskman.wait(timeout.msecs);

            if (slot_idx !in this.timers[timer_type])  // timer cancelled
                return;
            else
                this.timers[timer_type].remove(slot_idx);

            callCPPDelegate(callback);
        });
    }
}
