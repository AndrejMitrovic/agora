/*******************************************************************************

    Bindings for quorum/QuorumTracker.h

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module scpd.quorum.QuorumTracker;

import scpd.Cpp;
import scpd.scp.SCP;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types;

extern (C++, `stellar`):

// helper class to help track the overall quorum over time
// a node tracked is definitely in the transitive quorum.
// If its associated quorum set is empty (nullptr), it just means
// that another node has that node in its quorum set
// but could not explore the quorum further (as we're missing the quorum set)
// Nodes can be added one by one (calling `expand`, most efficient)
// or the quorum can be rebuilt from scratch by using a lookup function
extern(C++, class) public class QuorumTracker
{
public:
    alias QuorumMap = unordered_map!(NodeID, SCPQuorumSetPtr);

private:
    SCP* mSCP;
    QuorumMap mQuorum;

public:
    this(SCP* scp);

    // returns true if id is in transitive quorum for sure
    bool isNodeDefinitelyInQuorum(const ref NodeID id);

    // attempts to expand quorum at node `id`
    // expansion here means adding `id` to the known quorum
    // and add its dependencies as defined by `qset`
    // returns true if expansion succeeded
    //     `id` was unknown
    //     `id` was known and didn't have a quorumset
    // returns false on failure
    // if expand fails, the caller should instead use `rebuild`
    bool expand(const ref NodeID id, SCPQuorumSetPtr qSet);

    // replaces 'rebuild' taking an std::function so we can use it with D delegates
    extern (D) public final void rebuild (SCPQuorumSetPtr delegate(const ref NodeID) lookup)
    {
        static extern(C++) SCPQuorumSetPtr call (void* func, const ref NodeID node_id)
        {
            auto dg = cast(SCPQuorumSetPtr delegate(const ref NodeID)*)func;
            return (*dg)(node_id);
        }

        quorum_tracker_rebuild(cast(void*)this, &call, cast(void*)&lookup);
    }

    // returns the current known quorum
    ref const(QuorumMap) getQuorum() const;
}

private void quorum_tracker_rebuild (void* quorum_tracker, void* cb, void* dg);
