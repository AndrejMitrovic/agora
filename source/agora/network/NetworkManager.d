/*******************************************************************************

    Expose facilities used by the `Node` to communicate with the network

    The `NetworkManager` is responsible for managing the view of the network
    that a `Node` has.
    Things such as peer blacklisting, prioritization (which peer is contacted
    first when a message has to be sent), etc... are handled here.

    In unittests, one can replace a `NetworkManager` with a `TestNetworkManager`
    which provides a different client type (see `getClient`) in order to enable
    in-memory network communication.

    Copyright:
        Copyright (c) 2019 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.network.NetworkManager;

import agora.api.Validator;
import agora.common.BanManager;
import agora.consensus.data.Block;
import agora.consensus.data.Enrollment;
import agora.consensus.data.PreimageInfo;
import agora.common.crypto.Key;
import agora.common.Config;
import agora.common.Types;
import agora.common.Metadata;
import agora.common.Set;
import agora.common.Task;
import agora.consensus.data.Transaction;
import agora.network.NetworkClient;
import agora.node.Ledger;
import agora.utils.Log;

import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types : StellarHash = Hash;

import vibe.web.rest;

import std.algorithm;
import std.array;
import std.exception;
import std.format;
import std.random;

import core.stdc.time;
import core.time;

mixin AddLogger!();

/// Ditto
public class NetworkManager
{
    /// Config instance
    protected const NodeConfig node_config = NodeConfig.init;

    /// Task manager
    private TaskManager taskman;

    /// The connected nodes
    protected NetworkClient[PublicKey] peers;

    /// The quorum set
    protected SCPQuorumSet[StellarHash] quorum_sets;

    /// The addresses currently establishing connections to.
    /// Used to prevent connecting to the same address twice.
    protected Set!Address connecting_addresses;

    /// All known addresses so far
    protected Set!Address known_addresses;

    /// Addresses are added and removed here,
    /// but never added again if they're already in known_addresses
    protected Set!Address todo_addresses;

    /// Address ban manager
    protected BanManager banman;

    ///
    private Metadata metadata;

    /// Initial seed peers
    const(string)[] seed_peers;

    /// DNS seeds
    private const(string)[] dns_seeds;

    /// If we're a validator, we should connect to all of our quorum peers first
    private Set!PublicKey required_peer_keys;

    /// Ctor
    public this (in NodeConfig node_config, in BanManager.Config banman_conf,
        in string[] peers, in QuorumConfig quorum_conf, in string[] dns_seeds,
        Metadata metadata, TaskManager taskman)
    {
        this.taskman = taskman;
        this.node_config = node_config;
        this.metadata = metadata;
        this.seed_peers = peers;
        this.dns_seeds = dns_seeds;
        this.banman = this.getBanManager(banman_conf, node_config.data_dir);

        import std.algorithm;
        import std.array;
        import std.typecons;

        void getNodes (in QuorumConfig conf, ref Set!PublicKey nodes)
        {
            foreach (node; conf.nodes)
            {
                if (node != node_config.key_pair.address)  // filter ourselves
                    nodes.put(node);
            }

            foreach (sub_conf; conf.quorums)
                getNodes(sub_conf, nodes);
        }

        if (node_config.is_validator)
            getNodes(quorum_conf, this.required_peer_keys);
    }

    /***************************************************************************

        Called when there was an incoming connection from another node via
        the handshake() API.

        The current node will attempt to establish a connection with the
        given address, and register this incoming node as a listener.
        That node will receive gossiped transactions / SCPEnvelopes / etc.

        Params:
            address = the address of the incoming connection

    ***************************************************************************/

    public void onIncomingConnection (Address address)
    {
        this.taskman.runTask(()
        {
            // wait a little, to avoid cyclic handshake calls
            this.taskman.wait(1.seconds);

            if (!this.banman.isBanned(address) &&
                address !in this.connecting_addresses)
            {
                this.connecting_addresses.put(address);
                this.tryConnecting(address);
            }
        });
    }

    /***************************************************************************

        Returns:
            the quorum set associated with the given hash, or null if not found

    ***************************************************************************/

    public SCPQuorumSet* getQuorumSet (StellarHash hash) nothrow
    {
        return hash in this.quorum_sets;
    }

    /***************************************************************************

        Returns:
            the address of this node (can be overriden in unittests)

    ***************************************************************************/

    protected string getAddress ()
    {
        // allocates, called infrequently though
        return format("http://%s:%s", this.node_config.address,
            this.node_config.port);
    }

    /***************************************************************************

        Discover the network.

        Go through the list of peers in the node configuration,
        connect to all of the validators (if we're a validator node),
        and keep discovering more full nodes nodes in the network
        until maxPeersConnected() returns true.

    ***************************************************************************/

    public void discover ()
    {
        this.banman.load();

        // add our own address to the list of banned addresses to avoid
        // the node communicating with itself
        this.banman.banUntil(this.getAddress(), time_t.max);

        assert(this.metadata !is null, "Metadata is null");
        this.metadata.load();

        // if we have peers in the metadata, use them
        if (this.metadata.peers.length > 0)
        {
            this.addAddresses(this.metadata.peers);
        }
        else
        {
            // add the IP seeds
            this.addAddresses(Set!Address.from(this.seed_peers));

            // add the DNS seeds
            if (this.dns_seeds.length > 0)
                this.addAddresses(resolveDNSSeeds(this.dns_seeds));
        }

        log.info("Discovering from {}", this.todo_addresses.byKey());

        while (!this.minPeersConnected())
        {
            this.connectNextAddresses();
            this.taskman.wait(this.node_config.retry_delay.msecs);
        }

        log.info("Discovery reached. {} peers connected.", this.peers.length);

        // the rest can be done asynchronously as we can already
        // start validating and voting on the blockchain
        this.taskman.runTask(()
        {
            while (1)
            {
                if (!this.peerLimitReached())
                    this.connectNextAddresses();

                this.taskman.wait(this.node_config.retry_delay.msecs);
            }
        });
    }

    /***************************************************************************

        Periodically retrieve the latest blocks and apply them to the
        provided ledger.

        Params:
            ledger = the Ledger to apply received blocks to
            isNominating = if we're currently nominating then do not
                           alter the state of the ledger

    ***************************************************************************/

    public void startPeriodicCatchup (Ledger ledger,
        bool delegate() @safe isNominating)
    {
        this.taskman.runTask(
        ()
        {
            // periodic task
            while (1)
            {
                this.getBlocksFrom(
                    ledger.getBlockHeight() + 1,
                    blocks => blocks.all!(block =>
                        // do not alter the state of the ledger if
                        // we're currently nominating
                        !isNominating() && ledger.acceptBlock(block)));

                this.taskman.wait(2.seconds);
            }
        });
    }

    /***************************************************************************

        Get a BanManager instance.

        Can be overriden in unittests to test ban management
        without relying on a clock.

        Params:
            banman_conf = ban manager config
            data_dir = path to the data directory

        Returns:
            an instance of a BanManager

    ***************************************************************************/

    protected BanManager getBanManager (in BanManager.Config banman_conf,
        cstring data_dir)
    {
        return new BanManager(banman_conf, data_dir);
    }

    /***************************************************************************

        Retrieve blocks starting from block_height up to the highest block
        that's available from the connected nodes.

        As requests may fail, this function should be called with a timer
        to ensure consistency of the node's ledger with other nodes.

        Params:
            block_height = the starting block height to begin retrieval from
            onReceivedBlocks = delegate to call with the received blocks
                               if it returns false, further processing of blocks
                               from the same node is rejected due to invalid
                               block data.

    ***************************************************************************/

    private void getBlocksFrom (ulong block_height,
        scope bool delegate(const(Block)[]) @safe onReceivedBlocks) nothrow
    {
        struct Pair { size_t height; NetworkClient client; }

        static Pair[] node_pairs;
        node_pairs.length = 0;
        assumeSafeAppend(node_pairs);

        // return size_t.max if getBlockHeight() fails
        size_t getHeight (NetworkClient node)
        {
            try
                return node.getBlockHeight();
            catch (Exception ex)
                return size_t.max;
        }

        auto node_pair = this.peers.byValue
            .map!(node => Pair(getHeight(node), node))
            .filter!(pair => pair.height != ulong.max)  // request failed
            .each!(pair => node_pairs ~= pair);

        node_pairs.sort!((a, b) => a.height > b.height);

        LNextNode: foreach (pair; node_pairs) try
        {
            if (block_height > pair.height)
                continue;  // this node does not have newer blocks than us

            log.info("Retrieving latest blocks from {}..", pair.client.address);
            const MaxBlocks = 1024;

            do
            {
                auto blocks = pair.client.getBlocksFrom(block_height, MaxBlocks);
                if (blocks.length == 0)
                    continue LNextNode;

                log.info("Received blocks [{}..{}] out of {}..",
                    blocks[0].header.height, blocks[$ - 1].header.height,
                    pair.height + 1);  // +1 for genesis block

                // one or more blocks were rejected, stop retrieval from node
                if (!onReceivedBlocks(blocks))
                    continue LNextNode;

                block_height += blocks.length;
            }
            while (block_height < pair.height);
        }
        catch (Exception ex)
        {
            log.error("Couldn't retrieve blocks: {}. Will try again later..",
                ex.msg);
        }
    }

    /// Dump the metadata
    public void dumpMetadata ()
    {
        this.banman.dump();
        this.metadata.dump();
    }

    /// Attempt connecting with the given address
    private void tryConnecting (Address address)
    {
        // banned address, try later
        if (this.banman.isBanned(address))
        {
            this.connecting_addresses.remove(address);
            this.todo_addresses.put(address);
            return;
        }

        log.info("Establishing connection with {}...", address);
        auto node = new NetworkClient(this.taskman, this.banman, address,
            this.getClient(address, this.node_config.timeout.msecs),
            this.node_config.retry_delay.msecs,
            this.node_config.max_retries);

        while (1)
        {
            try
            {
                node.handshake(this.getAddress());
                if (node.quorum_hash != StellarHash.init)
                    this.quorum_sets[node.quorum_hash] = node.quorum_set;
                this.connecting_addresses.remove(node.address);
                this.required_peer_keys.remove(node.key);

                if (this.peerLimitReached())
                    return;

                log.info("Established new connection with peer: {}", node.key);
                this.peers[node.key] = node;
                this.metadata.peers.put(node.address);
                break;
            }
            catch (Exception ex)
            {
                // try again, unless banned
                if (this.banman.isBanned(node.address))
                {
                    this.connecting_addresses.remove(node.address);
                    this.todo_addresses.put(node.address);  // try later
                    log.info("Handshake with node {} failed: {}. Node banned until {}",
                        node.address, ex.message, this.banman.getUnbanTime(node.address));
                    return;
                }
            }
        }

        // keep asynchronously polling for complete network info,
        // until complete peer info is returned, or we've
        // established all necessary connections,
        // or the node was banned
        while (!this.minPeersConnected())
        {
            try
            {
                auto net_info = node.getNetworkInfo();
                if (net_info.state == NetworkState.Complete)
                    return;  // done

                // if it's incomplete give the client some time to connect
                // with other peers and try again later
                log.info("[{}] ({}): Peer info is incomplete. Retrying in {}..",
                    node.address, node.key, this.node_config.retry_delay);
                this.taskman.wait(this.node_config.retry_delay.msecs);
            }
            catch (Exception ex)
            {
                // try again, unless banned
                if (this.banman.isBanned(node.address))
                {
                    this.connecting_addresses.remove(node.address);
                    this.todo_addresses.put(node.address);  // try later
                    log.info("Retrieval of peers from node {} failed: {}. " ~
                        "Node banned until {}", node.address, ex.message,
                        this.banman.getUnbanTime(node.address));
                    return;
                }
            }
        }
    }

    /// Received new set of addresses, put them in the todo & known IP list
    private void addAddresses (Set!Address addresses)
    {
        foreach (address; addresses)
        {
            // go away
            if (this.banman.isBanned(address))
                continue;

            // make a note of it
            this.known_addresses.put(address);

            // not connecting? connect later
            if (address !in this.connecting_addresses)
                this.todo_addresses.put(address);
        }
    }

    /// start tasks for each new and valid address
    private void connectNextAddresses ()
    {
        // nothing to check this round
        if (this.todo_addresses.length == 0)
            return;

        auto random_addresses = this.todo_addresses.pickRandom();

        log.info("Connecting to next set of addresses: {}",
            random_addresses);

        foreach (address; random_addresses)
        {
            this.todo_addresses.remove(address);

            if (!this.banman.isBanned(address) &&
                address !in this.connecting_addresses)
            {
                this.connecting_addresses.put(address);
                this.taskman.runTask(() { this.tryConnecting(address); });
            }
        }
    }

    ///
    private bool minPeersConnected ()  pure nothrow @safe @nogc
    {
        return this.required_peer_keys.length == 0 &&
            this.peers.length >= this.node_config.min_listeners;
    }

    private bool peerLimitReached ()  nothrow @safe
    {
        return this.required_peer_keys.length == 0 &&
            this.peers.byValue.filter!(node =>
                !this.banman.isBanned(node.address)).count >=
                    this.node_config.max_listeners;
    }

    /// Returns: the list of node IPs this node is connected to
    public NetworkInfo getNetworkInfo () pure nothrow @safe @nogc
    {
        return NetworkInfo(
            this.minPeersConnected()
                ? NetworkState.Complete : NetworkState.Incomplete,
            this.known_addresses);
    }

    /***************************************************************************

        Instantiates a client object implementing `API`

        This function simply returns a client object implementing `API`.
        In the default implementation, this returns a `RestInterfaceClient`.
        However, it can be overriden in test code to return an in-memory client.

        Params:
          address = The address (IPv4, IPv6, hostname) of this node
          timeout = the timeout duration to use for requests

        Returns:
          An object to communicate with the node at `address`

    ***************************************************************************/

    protected API getClient (Address address, Duration timeout)
    {
        import vibe.http.client;

        auto settings = new RestInterfaceSettings;
        settings.baseURL = URL(address);
        settings.httpClientSettings = new HTTPClientSettings;
        settings.httpClientSettings.connectTimeout = timeout;
        settings.httpClientSettings.readTimeout = timeout;

        return new RestInterfaceClient!API(settings);
    }

    /***************************************************************************

        Gossips the transaction to all the listeners.

        Params:
            tx = the transaction to gossip

    ***************************************************************************/

    public void gossipTransaction (Transaction tx) @safe
    {
        foreach (ref node; this.peers)
        {
            if (this.banman.isBanned(node.address))
            {
                log.trace("Not sending to {} as it's banned", node.address);
                continue;
            }

            node.sendTransaction(tx);
        }
    }

    /***************************************************************************

        Gossips the SCPEnvelope to the network of connected validators.

        Params:
            envelope = the SCPEnvelope to gossip to the network.

    ***************************************************************************/

    public void gossipEnvelope (SCPEnvelope envelope)
    {
        import std.stdio;
        //writefln("Gossiping %s from %s to %s",
        //    SCPStatementHash(envelope.statement).hashFull(),
        //    this.node_config.key_pair.address, this.peers);

        log.info("Gossiping {}",
            SCPStatementHash(envelope.statement).hashFull());

        foreach (ref node; this.peers)
        {
            if (this.banman.isBanned(node.address))
            {
                log.trace("Not sending to {} as it's banned", node.address);
                continue;
            }

            node.sendEnvelope(envelope);
        }
    }

    /***************************************************************************

        Sends the enrollment request to all the listeners.

        Params:
            enroll = the enrollment data to send

    ***************************************************************************/

    public void sendEnrollment (Enrollment enroll) @safe
    {
        foreach (ref node; this.peers)
        {
            if (this.banman.isBanned(node.address))
            {
                log.trace("Not sending to {} as it's banned", node.address);
                continue;
            }

            node.sendEnrollment(enroll);
        }
    }

    /***************************************************************************

        Sends the pre-image to all the listeners.

        Params:
            preimage = the pre-image information to send

    ***************************************************************************/

    public void sendPreimage (PreimageInfo preimage) @safe
    {
        foreach (ref node; this.peers)
        {
            if (this.banman.isBanned(node.address))
            {
                log.trace("Not sending to {} as it's banned", node.address);
                continue;
            }

            node.sendPreimage(preimage);
        }
    }
}

/*******************************************************************************

    Resolves IPs out of a list of DNS seeds

    Params:
        addresses = the set of DNS seeds

    Returns:
        The resolved set of IPs

*******************************************************************************/

private Set!Address resolveDNSSeeds (in string[] dns_seeds)
{
    import std.conv;
    import std.string;
    import std.socket : getAddressInfo, AddressFamily, ProtocolType;

    Set!Address resolved_ips;

    foreach (host; dns_seeds)
    try
    {
        log.info("DNS: contacting seed '{}'..", host);
        foreach (addr_info; getAddressInfo(host))
        {
            log.trace("DNS: checking address {}", addr_info);
            if (addr_info.family != AddressFamily.INET &&
                addr_info.family != AddressFamily.INET6)
            {
                log.trace("DNS: rejected non-IP family {}", addr_info.family);
                continue;
            }

            // we only support TCP for now
            if (addr_info.protocol != ProtocolType.TCP)
            {
                log.trace("DNS: rejected non-TCP node {}", addr_info);
                continue;
            }

            // if the port is set to zero, assume default Boa port
            auto ip = addr_info.address.to!string.replace(":0", ":2826");
            log.info("DNS: accepted IP {}", ip);
            resolved_ips.put(ip);
        }
    }
    catch (Exception ex)
    {
        log.error("Error contacting DNS seed: {}", ex.message);
    }

    return resolved_ips;
}

import agora.common.Hash : Hash, HashDg, hashPart, hashFull;

/// Adds hashing support to SCPStatement
public struct SCPStatementHash
{
    // sanity check in case a new field gets added.
    // todo: use .tupleof tricks for a more reliable field layout change check
    static assert(SCPNomination.sizeof == 80);

    /// instance
    const SCPStatement st;


    /***************************************************************************

        Compute the hash for SCPStatement.
        Note: trusted due to union access.

        Params:
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (scope HashDg dg) const nothrow @trusted @nogc
    {
        hashPart(st.nodeID, dg);
        hashPart(st.slotIndex, dg);
        hashPart(st.pledges.type_, dg);

        switch (st.pledges.type_)
        {
            case SCPStatementType.SCP_ST_PREPARE:
                computeHash(st.pledges.prepare_, dg);
                break;

            case SCPStatementType.SCP_ST_CONFIRM:
                computeHash(st.pledges.confirm_, dg);
                break;

            case SCPStatementType.SCP_ST_EXTERNALIZE:
                computeHash(st.pledges.externalize_, dg);
                break;

            case SCPStatementType.SCP_ST_NOMINATE:
                computeHash(st.pledges.nominate_, dg);
                break;

            default:
                assert(0);
        }
    }

    /***************************************************************************

        Compute the hash for a prepare pledge statement.

        Params:
            prep = the prepare pledge statement
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (const ref SCPStatement._pledges_t._prepare_t prep,
        scope HashDg dg) const nothrow @safe @nogc
    {
        hashPart(prep.quorumSetHash[], dg);
        hashPart(prep.ballot, dg);

        /// these two can legitimately be null in the protocol
        if (prep.prepared !is null)
            hashPart(*prep.prepared, dg);

        /// ditto
        if (prep.preparedPrime !is null)
            hashPart(*prep.preparedPrime, dg);

        hashPart(prep.nC, dg);
        hashPart(prep.nH, dg);
    }

    /***************************************************************************

        Compute the hash for a confirm pledge statement.

        Params:
            conf = the confirm pledge statement
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (const ref SCPStatement._pledges_t._confirm_t conf,
        scope HashDg dg) const nothrow @safe @nogc
    {
        hashPart(conf.ballot, dg);
        hashPart(conf.nPrepared, dg);
        hashPart(conf.nCommit, dg);
        hashPart(conf.nH, dg);
        hashPart(conf.quorumSetHash[], dg);
    }

    /***************************************************************************

        Compute the hash for an externalize pledge statement.

        Params:
            ext = the externalize pledge statement
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (
        const ref SCPStatement._pledges_t._externalize_t ext, scope HashDg dg)
        const nothrow @safe @nogc
    {
        hashPart(ext.commit, dg);
        hashPart(ext.nH, dg);
        hashPart(ext.commitQuorumSetHash[], dg);
    }

    /***************************************************************************

        Compute the hash for a nomination pledge statement.

        Params:
            nom = the nomination pledge statement
            dg = Hashing function accumulator

    ***************************************************************************/

    public void computeHash (const ref SCPNomination nom, scope HashDg dg)
        const nothrow @safe @nogc
    {
        hashPart(nom.quorumSetHash[], dg);
        hashPart(nom.votes[], dg);
        hashPart(nom.accepted[], dg);
    }
}

/// ditto
nothrow @safe @nogc
unittest
{
    SCPStatement st;
    SCPBallot prep;
    SCPBallot prep_prime;

    import std.conv;

    () @trusted {
        st.pledges.prepare_ = SCPStatement._pledges_t._prepare_t.init;
        st.pledges.prepare_.prepared = &prep;
        st.pledges.prepare_.preparedPrime = &prep_prime;
        st.pledges.type_ = SCPStatementType.SCP_ST_PREPARE;
    }();
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0x266223f3385aecddc64e02e21cb655d1693002d5da8e49e2c9a73afe0cf3ceac4" ~
        "90b28fdfb42b0d67e7796593907947fb227b1045cf9b14785ba7d34c4305dbf"));

    prep.counter++;
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0xdc8135b6c7757a1f68db0d792be67764ae3337e02b9cb2cd460fe3fa051a435b1" ~
        "7a82ebd71d9ae00b36a9fcb90fd2b1e1d01bffbe335e1eda7de14ebf1c70a8d"));

    prep_prime.counter++;
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0x0f4629c0571c806488b6ff737053963e42dc72427ac4de8293b69c674102efbd5" ~
        "709928a32c60008359bd518da08c8a79a0ed38b722f61f741fc7df0f96bd99a"));

    () @trusted { st.pledges.prepare_.prepared = null; }();
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0x6f056828fa1f7d59fca4279d37a3a933da1360718270872f9c37be67ab10aabdb" ~
        "e0e4d889509f27f4957dc13b0082ac61d1acce19e599a89440679d36fe42ff9"));

    () @trusted { st.pledges.prepare_.preparedPrime = null; }();
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0x328bcea198398bb6a52036b641f0fcc50ae7d3b97490bfe1e020441d158104458" ~
        "29a63bb892da3ce2e539e1aa5a9f688695aefd54f967c197415ff834f0f0b22"));

    () @trusted { st.pledges.nominate_ = SCPNomination.init; }();
    st.pledges.type_ = SCPStatementType.SCP_ST_NOMINATE;
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0xc359847b8ddce220c896386c6b05fd12acb36fb850bd4b3959cf97516b9360eda" ~
        "98f9728911e678c342e23e38e300b1872faeddfa4ccd619404f3d9b7fc17439"));

    () @trusted { st.pledges.confirm_ = SCPStatement._pledges_t._confirm_t.init; }();
    st.pledges.type_ = SCPStatementType.SCP_ST_CONFIRM;
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0x118121cc790639f11190bb5ea1f8023c7889f8484b69b2d13b7056f831b2b5741" ~
        "afe7511a59d24f193fcce5c19080a5ca74ebc8487f1f340d70092066cd11f90"));

    () @trusted { st.pledges.externalize_ = SCPStatement._pledges_t._externalize_t.init; }();
    st.pledges.type_ = SCPStatementType.SCP_ST_EXTERNALIZE;
    assert(SCPStatementHash(st).hashFull() == Hash.fromString(
        "0x3c5a1a66ecf0c1e8992f448718fb1f4a6cbfb9527adba408644caefda8c1b1353" ~
        "98dbc0c33174280e8b0a5fb835dc707f06394c1205f8be545e5f70c771b421d"));
}
