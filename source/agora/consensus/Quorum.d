/*******************************************************************************

    Contains the quorum generator algorithm.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.Quorum;

import agora.common.Amount;
import agora.common.BitField;
import agora.common.Config;
import agora.common.crypto.Key;
import agora.common.Hash;
import agora.common.Set;
import agora.consensus.data.Enrollment;
import agora.consensus.data.UTXOSet;
import agora.consensus.EnrollmentManager;
import agora.utils.PrettyPrinter;

import scpd.Cpp;
import scpd.types.Stellar_SCP;
import scpd.types.Stellar_types : StellarHash = Hash, NodeID;
import scpd.types.Utils;
import scpd.types.XDRBase;

import scpd.quorum.QuorumIntersectionChecker;
import scpd.quorum.QuorumTracker;

import std.algorithm;
import std.array;
import std.conv;
import std.format;
import std.math;
import std.random;
import std.range;
import std.string;
import std.typecons;

import std.stdio;

/// limits the number of nodes in a quorum set
private enum MAX_NODES_IN_QUORUM = 7;

/*******************************************************************************

    Build the quorum configuration for the entire network of the given
    registered enrollments. The random seed is used to shuffle the quorums.

    Params:
        enrolls = the array of registered enrollments
        finder = the delegate to find UTXOs with
        rand_seed = the source of randomness

    Returns:
        the map of all quorum configurations

*******************************************************************************/

public QuorumConfig[PublicKey] buildQuorumConfigs ( Enrollment[] enrolls,
    UTXOFinder finder, Hash rand_seed )
{
    Amount[PublicKey] all_stakes = buildStakes(enrolls, finder);
    NodeStake[] stakes_by_price = orderStakesDescending(all_stakes);

    const Amount min_quorum_amount = Amount(
        cast(ulong)(10_000_000 * (0.67 *  // todo: add multiply() support
            stakes_by_price.map!(stake => stake.amount.integral)
                .sum)));

    auto quorums = buildQuorums(stakes_by_price, min_quorum_amount, rand_seed);
    verifyQuorumsSanity(quorums);
    verifyQuorumsIntersect(quorums);

    return quorums;
}

///
unittest
{
    import std.conv;

    // 2 nodes
    foreach (seed_idx; 0 .. 16)
    {
        auto rand_seed = hashFull(seed_idx);
        auto quorums = buildQuorumConfigs(genEnrollments(2).expand, rand_seed);
        auto n1 = getTestKey(0);
        auto n2 = getTestKey(1);
        auto q1 = quorums[n1];
        auto q2 = quorums[n2];
        assert(q1.threshold == 2);
        assert(q1.nodes == [n1, n2], format("Expected %s. Got %s", [n1, n2], q1.nodes));
        assert(q1.quorums.length == 0);
    }
}

/*******************************************************************************

    Build the quorum configuration for the entire network of the given
    the provided stakes enrollments. The random seed is used to shuffle the
    quorums.

    Each node will assign nodes to its quorum until either the minimum
    staken amount is reached, or MAX_NODES_IN_QUORUM has been reached.

    Params:
        stakes = the list of stakes, in descending order
        min_amount = the minimum amount a node's quorum's sum of stake should
                     be reached (unless MAX_NODES_IN_QUORUM is reached first)
        rand_seed = the source of randomness

    Notes:
        dice() should be replaced / improved to be more efficient,
        see also https://issues.dlang.org/show_bug.cgi?id=5849

*******************************************************************************/

private QuorumConfig[PublicKey] buildQuorums (in NodeStake[] stakes,
    const Amount min_amount, in Hash rand_seed)
{
    QuorumConfig[PublicKey] quorums;
    Set!PublicKey used_qnodes;
    auto assigned_nodes = BitField!uint(stakes.length);

    foreach (node; stakes)
    {
        Amount quorum_sum;  // sum of the staked amount of the quorum for this node

        // dice() can return duplicates
        auto added_nodes = BitField!uint(stakes.length);
        auto rnd_gen = getGenerator(node.key, rand_seed);
        auto quorum = &quorums.require(node.key, QuorumConfig.init);

        while (quorum_sum < min_amount &&
            quorum.nodes.length < MAX_NODES_IN_QUORUM)
        {
            const idx = dice(rnd_gen,
                stakes.map!(stake => stake.amount.integral));

            if (added_nodes[idx])
                continue;

            auto qnode = stakes[idx];
            quorum.nodes ~= qnode.key;
            assigned_nodes[idx] = true;
            added_nodes[idx] = true;

            if (!quorum_sum.add(qnode.amount))
                assert(0);
        }

        // +1 because the node itself also counts as one
        const majority = max(1, cast(size_t)floor(0.67 * (1 + quorum.nodes.length)));
        quorum.threshold = majority;
    }

    assignLeftoverNodes(rand_seed, stakes, assigned_nodes, quorums);

    foreach (key, ref config; quorums)
    {
        // we want a predictable order for easy verifiability
        sort(config.nodes);
    }

    return quorums;
}

/*******************************************************************************

    For any unassigned nodes, assign each to a random node's quorum.

    Params:
        rand_seed = the source of randomness
        stakes = all the node stakes
        assigned_nodes = all assigned nodes
        quorums = existing quorums which might be updated

*******************************************************************************/

private void assignLeftoverNodes (in Hash rand_seed, in NodeStake[] stakes,
    /*in*/ BitField!uint assigned_nodes, QuorumConfig[PublicKey] quorums)
{
    foreach (idx; 0 .. assigned_nodes.length)
    {
        if (!assigned_nodes[idx])
            continue;

        auto qnode = stakes[idx];

        auto lucky_node = stakes
            .randomCover(getGenerator(qnode.key, rand_seed))
            .filter!(node => node.key != qnode.key)  // filter the node itself
            .front.key;

        auto lucky = lucky_node in quorums;
        assert(lucky !is null);

        // update threshold for the new majority
        const majority = max(1, cast(size_t)floor(0.67 * (1 + lucky.nodes.length)));
        lucky.threshold = majority;
    }
}

/*******************************************************************************

    Verify that the provided quorum sets are considered sane by SCP.

    The quorums are checked both pre and post-normalization,
    with extra safety checks enabled.

    Params:
        quorums = the quorum map of (node => quorum) to verify

    Throws:
        AssertError if the quorum is not considered sane by SCP.

*******************************************************************************/

private void verifyQuorumsSanity (QuorumConfig[PublicKey] quorums)
{
    import scpd.scp.QuorumSetUtils;

    foreach (key, quorum; quorums)
    {
        auto scp_quorum = toSCPQuorumSet(quorum);
        const(char)* reason;

        assert(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check before normalization: %s",
                    key.nice, quorum.toToml, reason.to!string));

        normalizeQSet(scp_quorum);
        assert(isQuorumSetSane(scp_quorum, true, &reason),
            format("Key %s with %s fails sanity check after normalization: %s",
                    key.nice, quorum.toToml, reason.to!string));
    }
}

/*******************************************************************************

    Verify that all the quorums intersect according to the quorum checker tool

    Params:
        quorums = the quorums to check

    Throws:
        AssertError if the quorum is not considered sane by SCP.

*******************************************************************************/

private void verifyQuorumsIntersect (QuorumConfig[PublicKey] quorums)
{
    auto qm = QuorumTracker.QuorumMap.create();

    foreach (key, quorum; quorums)
    {
        auto scp = toSCPQuorumSet(quorum);
        auto scp_quorum = makeSharedSCPQuorumSet(scp);

        auto hash = StellarHash(key);
        auto scp_key = NodeID(hash);

        qm[scp_key] = scp_quorum;
    }

    auto qic = QuorumIntersectionChecker.create(qm);
    assert(qic.networkEnjoysQuorumIntersection());

    auto splits = qic.getPotentialSplit();

    if (splits.first.length != 0 ||
        splits.second.length != 0)
    {
        writefln("Splits: first: %s second: %s",
            splits.first[].map!(node_id => PublicKey(node_id).prettify),
            splits.second[].map!(node_id => PublicKey(node_id).prettify));

        //CircularAppender().printConsole();
        assert(0);  // should not happen
    }
}

/*******************************************************************************

    Create a random number generator which uses the hash of the random seed
    and a node's public key as an initializer for the engine.

    Params
        node_key = the public key of a node
        rand_seed = the source of randomness

    Returns:
        a Mersenne Twister 64bit random generator

*******************************************************************************/

private auto getGenerator (PublicKey node_key, Hash rand_seed)
{
    /// very simplistic way of reducing a 64-byte blob to an 8-byte seed
    static ulong toSeed (Hash hash)
    {
        return (cast(ulong[])hash[]).reduce!((a, b) => a ^ b);
    }

    Mt19937_64 gen;
    gen.seed(toSeed(hashMulti(node_key, rand_seed)));
    return gen;
}

/// The pair of (key, stake) for each node
private struct NodeStake
{
    /// the node key
    private PublicKey key;

    /// the staken amount
    private Amount amount;
}

/*******************************************************************************

    For each enrollment find the staked amount from the associated UTXO
    in the Enrollment, and build a key => amount map.

    Params
        enrolls = the list of enrollments
        finder = UTXO finder delegate

    Returns:
        a mapping of all keys => staken amount

*******************************************************************************/

private Amount[PublicKey] buildStakes (Enrollment[] enrolls, UTXOFinder finder)
{
    Amount[PublicKey] stakes;
    foreach (enroll; enrolls)
    {
        UTXOSetValue value;
        assert(finder(enroll.utxo_key, size_t.max, value),
            "UTXO for validator not found!");
        assert(value.output.address !in stakes,
            "Cannot have multiple enrollments for one validator!");

        stakes[value.output.address] = value.output.value;
    }

    return stakes;
}

/*******************************************************************************

    Params:
        stake_map = the map of node keys => their stake

    Returns:
        a descending set of nodes based on their stakes

*******************************************************************************/

private NodeStake[] orderStakesDescending (Amount[PublicKey] stake_map)
{
    auto stakes = stake_map
        .byKeyValue
        .map!(pair => NodeStake(pair.key, pair.value))
        .array;

    stakes.sort!((a, b) => a.amount > b.amount);
    return stakes;
}

/*******************************************************************************

    Generates a .toml syntax file that can be used with the go-scp
    tool in https://github.com/bobg/scp/blob/master/cmd/lunch/lunch.go
    for easy testing.

    Format example:

        [alice]
        Q = {t = 2, m = [{n = "bob"}, {n = "carol"}]}

        [bob]
        Q = {t = 2, m = [{n = "alice"}, {n = "carol"}]}

        [carol]
        Q = {t = 2, m = [{n = "alice"}, {n = "bob"}]}

    Or nested:

        [alice]
        Q = {t = 1, m = [{q = {t = 2, m = [{n = "bob"}, {n = "carol"}]}},
                         {q = {t = 2, m = [{n = "dave"}, {n = "elsie"}]}}]}

    Params:
        quorums = the quorum set
        level = indentation level

*******************************************************************************/

private string toToml (QuorumConfig[PublicKey] quorums)
{
    return quorums.byKeyValue.map!(pair =>
        format("[%s]\n%s", pair.key.nice, toToml(pair.value)))
            .join("\n\n");
}

/// ditto
private string toToml (QuorumConfig config, size_t level = 0)
{
    string result;

    result ~= format("%s = {t = %s, m = [",
        level == 0 ? "Q" : "q",
        config.threshold);

    // nodes
    auto nodes = config.nodes
        .map!(qnode => format(`{n = "%s"}`, qnode.nice))
        .join(", ");

    result ~= nodes.to!string;

    // subquorums (recursive)
    if (config.quorums.length > 0)
    {
        result ~= ", ";
        auto subq = config.quorums
            .map!(qsub => format("{ %s}", toToml(qsub, level + 1)))
            .join(", ");

        result ~= subq.to!string;
    }

    result ~= "]}";
    return result;
}

/// Nicer formatting for [sets of] public keys
private auto nice (Set!PublicKey input)
{
    return input._set.byKey.map!(key => key.nice);
}

/// ditto
private string nice (PublicKey input)
{
    // convert arbitrary hashes into user-readable strings like "Andrew, Dave, etc"
    static string toUserReadable (Hash hash)
    {
        const names =
        [
            "Aaron",
            "Adam",
            "Alex",
            "Andrew",
            "Anthony",
            "Austin",
            "Ben",
            "Brandon",
            "Brian",
            "Charles",
            "Chris",
            "Daniel",
            "David",
            "Edward",
            "Eric",
            "Ethan",
            "Fred",
            "George",
            "Iain",
            "Jack",
            "Jacob",
            "James",
            "Jason",
            "Jeremy",
            "John",
            "Jonathan",
            "Joseph",
            "Josh",
            "Justin",
            "Kevin",
            "Kyle",
            "Luke",
            "Mark",
            "Martin",
            "Mathew",
            "Matthew",
            "Michael",
            "Nathan",
            "Nicholas",
            "Nick",
            "Patrick",
            "Paul",
            "Peter",
            "Philip",
            "Richard",
            "Robert",
            "Ryan",
            "Samuel",
            "Scott",
            "Sean",
            "Simon",
            "Stephen",
            "Steven",
            "Thomas",
            "Timothy",
            "Tyler",
            "William",
            "Zach",
        ];

        static size_t last_used;
        static string[Hash] hashToName;

        if (auto name = hash in hashToName)
        {
            return *name;
        }
        else
        {
            string name = names[last_used];
            last_used++;

            if (last_used >= names.length)
                assert(0);  // add more names plz

            hashToName[hash] = name;
            return name;
        }
    }

    return toUserReadable(input[].hashFull());
}

/// Generate a tuple pair of (Enrollment[], UTXOFinder)
version (unittest)
private auto genEnrollments (size_t enroll_count)
{
    import agora.common.Amount;
    import agora.consensus.data.Transaction;
    import agora.consensus.Genesis;

    TestUTXOSet storage = new TestUTXOSet;
    Enrollment[] enrolls;

    foreach (idx; 0 .. enroll_count)
    {
        // increasing amount of values, for the test
        Amount amount = Amount.MinFreezeAmount;
        foreach (i; 0 .. idx + 1)
            amount.add(Amount.MinFreezeAmount);

        Transaction tx =
        {
            type : TxType.Freeze,
            outputs: [Output(amount, getTestKey(idx))]
        };

        storage.put(tx);
    }

    foreach (utxo; storage.keys)
    {
        Enrollment enroll =
        {
            utxo_key : utxo,
            cycle_length : 1008
        };

        enrolls ~= enroll;
    }

    return tuple(enrolls, &storage.findUTXO);
}


version (unittest)
private PublicKey getTestKey (size_t idx)
{
    return KeyPair.fromSeed(Seed.fromString(pregen_seeds[idx])).address;
}

// using pregenerated seeds to test the determenistic behavior of the algorithm
// note: sorted for easier comparison with PublicKey[]
version (unittest)
private immutable pregen_seeds =
[
    "SA2ET2TX6HK2THTC2HNTTTUIRPCOVPYCAICVWHD5ENFIP3YEFPEN4N67",
    "SA3BUVIQVJZ5JLPMCRO5FU7D3XOYIMNCOJV6WCWGLVAQQQH6OVZRK7AH",
    "SA3ES4M6ZC7ECGWOH3C75NIE66OS27ZV56FMJQCU4NRKWVA6WSN4EC7A",
    "SA3KKMIPVFWC54KIZWO3JSF57O6HGLTLNHJOOAAN3V5ADRR7B25YFBAB",
    "SA3WV2XWBXCPQEZPJ3EYCMQIROHGLUCIP2M5R2P7JWFVGIEAW3SSTXI3",
    "SA46KRZR5XFZ4V7PQEQNOHQMLLCSNPZYPSCD4FJRYTAWUJ6PXQJF3ALS",
    "SA4C6SXL6GDVAQNLEMS7YNN6HKN5NEYTVYAWA3WFQKBHN5FVS72SFJA6",
    "SA4L3QPE3BSOR3PC6DUVRJEONEWT7ZDLZIL6TYPWTYTY2INANWFU5TXM",
    "SA4OWN3CF2DAXCTX6ANRB6PDBRBRT5SZBXAHUAUZJEABDJQP7S6YJSA2",
    "SA4UEJWCWFKOEDBRESZBOXT7BP2CD4J5TBSK2VIV26P53CCQGKTDKSEX",
    "SA4VX3DOL7PQZ4QZNNMD5XIGRFO67UUYNQVRV2IHVLVNQUY3RCGLBRYD",
    "SA4WK62LK4TGH7AQJV5IULK7WWDGUXZYOL3VOVDMP7JADSH2ANES7AX2",
    "SA7NEUIUDYLCDPIZVYT5SIQECKECTJMSYEVVWGPTODNJSVTZVAUUBXDN",
    "SAAB7SEPJYBNG63YDLBSEVDLUMIB5KPMNDOOAX4M3CTHX7BFXPMKMLLV",
    "SAACDG64DGPNXJTWEL4TBM3G3UR4FTHL7NKWDVDOJD6KSUF437AMWWAV",
    "SAAQZQUY4N73D6ZLPIZUY2TYDF2EHJJQQFL7TXJ6TGKHBYFSB3P24ER2",
    "SAAW6Q2JDOZHWF3EME2F4TXSKRPJFTEGKDFXRRXPS2EJVT6VP3IYKNOU",
    "SAB43JTPSVCVL5ZZKHF2APVB5X45RQIUMJKKZXGRDHKYZ3IZNKQ2KSPJ",
    "SACHUQ7N5DHIJKNNO4YO27CCBK2DT7WEP5ZMP6KQFL6722X3OSZBEC7A",
    "SACSTOE2UROE4TTGR3WLRE5BI5KR4WITLVTUATLRF7CEXTSSJNSECPAO",
    "SAEJHT4LTJQPJXOBHON2OANK3RIWHYXDMUTT63U3KGS6FXLZQJ5EL4UU",
    "SAEP7HH6PHKJZARLY33SOSONFUQ6VXVULN6JMIOJ57UX3YSSUFSMWXPO",
    "SAFITM4H4VZI5Q3PG5WFLEBQAIMT5C7M5N3DL4RHMYX3U5KFCU4GJHVG",
    "SAFQV3JHAAQM3NYTBOG5VI65JC66GVM7LQ2YPXZOC2S5V2WQOUF234U7",
    "SAGVJ3JR4O7CVB6ZOS76FK3ZZEBBJ7RUSBOJR7XBVMCGFKBGQSFZ2SS6",
    "SAH2T5IKSVKNG6S7KQHZAORDPUKJ4FLQVSPGRPZPJW4SKCGNVNGMNMUN",
    "SAHQZH4NDVKGEMURNALWXLGIPF6LI4VKPP2VFVZVLIPZCXKWKUUIF67N",
    "SAI45UJSDWVCLBGPCWAKBRMFJJJRGMBKFV7Y2V547FIMKG7SRYUY77XH",
    "SAIFS45TVW4JWIKMUNXY2UVZDF5UFBJQVICSFZIG26SA5BFBWLM7YU7P",
    "SAINISV2XBB5HE42PM3MRLYRGNYAFVDFIDIKAC2JKZ6UKE36HM7PNRQR",
    "SAJOOW54GPWWFMTBUKGN72E3IJPKSBU6LXBQB2KVTYKVZ6RK3ZMWY7OV",
    "SAKEY5AP6ERGV64XEXMCIEP5N7ZVIOH2ZCMW2DDXWQ7HUQ4WCPXKDW4S",
    "SALDKUFLM63EPIM73TJQQMZMKJLBONQTT2GOYT45EXEUATURT4ONUKMQ",
    "SALN44QGB3PCTI25BC6G2AIASJB4GOL5IWR2EJ3VW3ALSHPKTXOFBNKJ",
    "SALR7IE2O7PCZKAZFTLLIYVQ3LIUS7WTNATPMXSB6OSSI62JW4UQ6MDP",
    "SANQPAHZWL7PMBW3QUKRTF2GOV7SNBMA23XQ34LTMQQ4OFYEQQB4GPVD",
    "SAOB43HVXBKH2NLLLXTYKFOF6P2XCOVUGANCI22IZDSGFM2NVQIOAPUN",
    "SAP6DYQFWKHG3WQ3REX6VJEYNP4A3NIS5ENZXQ4BJTWZLJ6USDPLSOTW",
    "SAPA7HDD2JA6Q45EQIUXMBUNFTCCIA3TGWX6GNWNPF47TSAQRYMJNZAW",
    "SAPDPOZCHWQD6RRNK6ZCAWG4HJVCOR3YKM3PEA3JHI3ZXOUB4RO36OTV",
    "SAQ7BTOZJ4G7TECC6DD4G6QCRN6AUUXYZHUDXRDF672GFDNNKDR534MO",
    "SAQEQ475K4BTKTW5RRZGX6NGRM37SOPIEM3OGVD2WNZMGZHIFDE65KQQ",
    "SAR5W42DCT25H2BJT75CK4A7YBR3JT52D27JEL6X4C7JPZOZJCQHBOI7",
    "SARDEFGFB7I2BS3PDAPQLZXLCBARJPUO3TX3ZZKKSXN6UOU4ZRWL3UY3",
    "SASHHP7BAYKG7UWNGUWDRQT75PBYVQ2K3F475J2BNDSME5GNTS3ZX2CJ",
    "SASN3GQBF2UJD5C6AILBXEDSFNJYK7O52R3GT3HFAWYAO4V4MYSVJU32",
    "SAT7VZQTLY3S5QYPHYPVNE3XIKIRNNNUSR7IS4VIRZCSTKRTFRC6Y4VQ",
    "SATBU2ZDCWOU3AXWL6SW7Y5SGLD3Q3UWRJD2BC2K66T76C3CNELF6JZA",
    "SATDNRQ56C2MWFCKHG7JNT4POSGGQSYQCVVOIOINZF2XBF7UIXZIKOBS",
    "SAU5UUNFJVOGEGGI52NLRJLRYCERGX4ACQMFYXYWADELX7GRRIDYLFPF",
    "SAUH5D3C5NFRO6XOYBC23VTVIMEXGUFB4FJQRK2WEIOVRJ5RVCMOSOCC",
    "SAV3NTUPZCKUDM7IALYMM6KOZBIBG256QUISQEUGQALWHRFEEBZX5MVQ",
    "SAVSOLLRFSFY66RDFPAUF7FV7S6XMYSS222PGVSXLZDJOHR7QOI2LTBL",
    "SAVTHZUIURET5QKUOT2FSL7YKEHMDACXWI4GDN3XOUOZAQJP5VMDLYWE",
    "SAVX7N3LOS3QEJENDMQJ5RUJGWYAUTK7P5BWFUSLHRBKH3IUFSOY2LDZ",
    "SAXEOVH52XG3RT77CBXDUTGH5KKMBBEQ444FM4RS3II3FTEXZXX5ILX4",
    "SAYCEKZOJOWQQZNZ25GZQLCO4N76PHRQ5D2XJIFWG3NGGLVWJL45HKJD",
    "SAYHVSHRSACT5XPUMSEGN53CHXMN37R4VDOZWKYG34EBVEFE5DJAWP5C",
    "SAYTIAI5WWUPH3HXLQBS5SJDNBR226TYWPEAJOPQG3UFUQF5UAPSABWA",
    "SAZAAGLAG5TO4EHP6QLOT6JEYKUSSXUW3SODIXRMEXPFCWKHTQZX7G6W",
    "SB2R6PWVM2TEUEY7KYAGEA6ZFAQZGUBJOX2XWWUHDWYVQDAXVLR6JTMQ",
    "SB34TUEXAXDGBH7RBJM7VNA5CHU52B5N6K6IYTYL3C35XCIOG5LUHH24",
    "SB3GJFPE7HZ7PY6UWHDPSVUXSIHAPGU3NLRISBR4FGY5QJ3GQPFZSSZF",
    "SB4CCMDOQJK7LHS6BAZ2PMB4IMYW26CP25RGBYXZCLMP33GGWFYSF2XQ",
    "SB4KHA7OCAR47XBDLRBSSXXERFV47ZG4OTIAIYFLGACZU2VJCBM5DXR6",
    "SB4LWXDJ4WFEEA6FDSTA7HFJONPOPPBUWDPC5A2PSWYBOOT6ZIHAWA75",
    "SB4OJLBPOMMHOZZIWI5UCXZM63MJQDU4Y664XAJID7KLGYQYZ3BJCOIH",
    "SB4WBKEX4YZK76RVKJJCA73DKJYWPFLH4G4FZESEU4BBSLQ5MQAIXIBG",
    "SB5BWZAVKI7G5IKAD6PEGYEYEEWOR4KZXITQ6HOZAQIHMYJHW5HEQYAS",
    "SB5P6VXKJLE5ZJ2AXH3JQ4TWGHQQIHVUXT7QESQ35HZK6OTMNAC67LUJ",
    "SB74S7CCG7BQH3CHCL3C3APRAXL7YWT2YHNNFU7UUBUKFWVPM7NMXLCW",
    "SBA3OWQAWNYGTBO56L4YINU7UUTFIRY5PAAYQO7UAFCRMA4O53M57FUV",
    "SBAQL62QGPLFBGUOFUZAMM2AV6CZMY6ILBIJFRT4BI23LK7NWWJISR53",
    "SBAUXQLV6VN5ZS2SIOQXPNZQTUVNB7XYLOVZ62QO67OB5RTKB6HNDDIK",
    "SBC36RNNPQNSMHRCR37GFBGGOTPIN5CAYD3LVC64BW5GOI6ZIYQIEUPD",
    "SBCCVR7CKMCFL3L6KG2MZ3CAAJIPOOAL34HIWZ7QC33DCHT7Z4DGYKYA",
    "SBD4N3UYSW7GKLHJMLBZRGKFNNHUY74ETARQHY7GXQP36WKRJUIHXLXB",
    "SBDBO3L7RIFIW72XMIFBT3RKWT5N4F2QCK4SXWC3PJYVYCK6D5L5LOWN",
    "SBDP62AQ6GCOMYYD3PO5PGWY5EWYUGTMDXZYVVO4BBTODWB3UTVCMH4P",
    "SBDYODGO6PJDMT3JEISNLGXRIJOIKQRQ6MZFIJMGT4TOSF7LOHTEBNOR",
    "SBEDB5F73HEF4WADSE2W5P4H4UQHY2WHZZYWOWA7KWPCVEK6BAT6F7XP",
    "SBEDSTSSFVXY6XBLEB54CEZ6HUO7LCUR67VAQYQPYY4YG7ZMVYZLTVBA",
    "SBEGTUYRASEQ3IEMHRVMO6RIQFQ4S7B3JH4XSEFE3HBGUT7QPYVBVE6E",
    "SBFCJHUI7WIRKUP7JNCXJLVEI4Z5PMJJRN2OJWIKZT5EIAXS55WLGNOI",
    "SBFJ2EGCCL6OCDB5VRB4Z4JTCTGHWQKKKSGQFNLPVUAGOXBK3CJWKZOX",
    "SBFSTU2WK674PFATKKURJTNVMNJCGVIDKG2VFL7LKITCPLKOIAMJTKFM",
    "SBFVARPGGZ4KDQQKKJQVDCFSFDJRS3ISCHKTF7U3AU4KUATRSA2GQ4XB",
    "SBFWDRNV6JHXYYKGNLU2DCEZEY6JCRHLZFXNJLF3O4MUPCAXSZD2L5BL",
    "SBGMRVY6XJWVOQXTWG57QP5TZU5QHXA2BUKCCVXR2GMZQQ2DXAQ44OBI",
    "SBHGJU6NQ6YUOIHYKTTHKMMI7WJBEPA6Q4DFEPHLTBDZQ6WMWXOZNBY3",
    "SBHVJGLUANTSUSPV77PILZZ6ZJLD6EG4AYF2TW7LXMJR4HRVQ4BFL3H6",
    "SBIRGJ2S3PG5UYIFLCUW2FCM33S3ZW4EMHLB7V5OAOWPQU44SRBNX7RB",
    "SBIUQLCUGXSXWCD7AHKMNMTO43VV5YJ4RZAA7MDVGX7VCMUHHSOV3TJO",
    "SBJXXXECD2BLA6V5NMEOS3GNJM2325SLZ6XPDJ62JMDMO6JLDYQOONAR",
    "SBKM4TKYDNIAKAFISZONAEVCXSIHSECJBS66TJAC2XIN2TQODP7ZDLHR",
    "SBKSUKSOVPZSPTRUVUJW7OI24YZBPQWVSDGEGNSQKFMV5ZYFFNSBXCZ5",
    "SBKTQE6RHF7KU6I6F32GKD4RPSKD2ML7RFYTE4EW3E23HVDWXTPS57FP",
    "SBKVR4CLEKD2MIAIBF4AXAMXKK6LZRXJ6LUG4B2AFOFAKV7J2CCV4DDI",
    "SBL54W5GW6ASSCN6FM46JSIGBAEZKKXIK5HCR4SQNG6MH7O2SFEZRU6U",
    "SBLBPR4M3R54MNYMUN6M76ACAP673WI3ZZRQ3AQFDNTPLXNRULEM6SZL",
    "SBMQKKNZVQ2NIYGGOWXAPDU76EL2CKTSRJEZWAUDFRS75XSVQEGTWPNV",
    "SBODCWBXREW4ZSOYD2PDSH4FWCQWLFMKPZKTJZGOPBRMNK4OFSQBJEWS",
    "SBOM4DSOOI5JVXSSI2YFXYLOM6ZRKRFYJD4ULIIFKU4XNYHE3DNB5FFP",
    "SBOZO2HSSPPNLB4HRW6HE4QOGSWIPZJBYQLZDKXDLBGKZXNDLRGCE7TH",
    "SBP5BZ6XRWPWUEVWQCBBFIJM64OHEJSIVRNYVYXEZZZUWTSERXUY6XVL",
    "SBPNCIU5N2PIGCWLFEZP5XZUZYL6S7UTRGQ4QOQK6GJJMSTOPZBER3RE",
    "SBPOFT7RFCWYPASV63PX5A2E2NGGF2WSCJRV4C7LE7EEI5LI62YBTYTG",
    "SBQZEO2BUJTK4CR7EC2FOMP6AIPYGJVQYGXLHKLD74PWAVAZBORHIDBW",
    "SBQZYYILQYJJSJGAW6H4ZHNGNUEYC5GSQZ54BKH3QVHKROWMFCIQANDQ",
    "SBR6IDT4RNJDQJWNSDNKDEXT4XF4V27KUPG24BY3NU46RU2U6FSNLOYB",
    "SBRYJAB77SBKQC73PD3SQ4RIGW4UI7XI6IR5K5D7FEFIOXM657B4FKIB",
    "SBSAOVGQRUBRWOOB6IMAAD52HGTPK4TQPUC4Q4YWUSJH3AOXHWCXE47O",
    "SBTFM3AW4HMDWLRJY3TVLT2CHCKCSTVMZKUICCEO67WX66ZRRK7FMHY4",
    "SBTT2LRBEJBQT6KYZ4NDLLPWSINUFGDLNLB2LCR6MXAV6ORY24V5U5ZE",
    "SBUDFGMATQA56YQ3ISSM4BVOFG3HLI2C4XJ3DJVYF3SYAYI2RQBBYRY4",
    "SBUKJF43JNEEKTG3ZQERYYAKJ54ITXSHITRICTNSLBIO2RPXTU2RIONW",
    "SBUN4IFTJDXE7UWKU2ROBNPZQYLTDIA4H3M6CXDB5FNHISXEFMAQH5VJ",
    "SBVEV5NT3GTHMUFAJEAQTY4FVCABQFN4JRWMSVNN5TH4J24M6GAVPJC4",
    "SBVJL4UUBNIAV4FVF542EJVVFJM7XW6GJPY26EV26ADAE24OSHC5V5SX",
    "SBVP6MTEZ7GVWJKGQFL7LUOFWLEMID5R5YPZYDO5IHPSU4KCWE5JGIQT",
    "SBW6SLKE7342EDCAZHAMROWFMN4AVUNQAL6K35EJI4HCFKRXT4DKRHDH",
    "SBWCFCXXC64ATCOTDYX5N7LVXM4FMKAQGG2QW4NTPDEVAXMVNUQR6CLC",
    "SBWVRJPGVFQJPCRHCXFUJ6RVQAJSEHYWOVT7IKHO7U6N4LP2DGKZBFUB",
    "SBWZGWC5AO4DMIO7JRCUKMWCAC4PSM32BHV6FWWO5GHQ7V52HDJ7SNS5",
    "SBXIHMM7ERWPTB4D7W4MOVBVALSCMVPQATM5F4CGDD3XMYK7KKLEUKDU",
    "SBY663C6PQ6GHXSRVGMKRW2JB3L4ZO6IDHMF6EELX3JP5SNAZNLYPRF4",
    "SBYKRYGTYYSLXTZLRDBTXHELA464QIVAD7DHXURXRHJDGFVZHZ72HLX2",
    "SBZGNBJKBYIG6RMPMXDLQ4IN6BPGDLCY23NK3UY6O7FMSG3C7Y3AZEDS",
    "SBZQ6AXB52WJ4MALZ6TDGI4YOQRLUHU5VGE2JOQBFHT4LAG3GBXAVXXS",
    "SC2KNTOSTBSQFJSQ5M5FDJ4IYVPRH4U7YDHIPKYQJ56NQGODPDNYEBMY",
    "SC2UTL6XYG62YHXAHIHA6CJ5FZDV3RO6OQO5HCNR3BMEASVALDRCDNIY",
    "SC2XUZZEBYZAC6W4UTLZIZEKRG6656TL523QLRBRIPJG6KV4B4MKTC6H",
    "SC3SLGGEGTNMSPYJPGHJ72PRYJQ5WKS6NARPVOSY37RGQ25CZSFPDN4D",
    "SC5J76DY25JBJPYQV5656YLBE5HFECU25GOOIT4RBHDZ5XJ6MNJG66NO",
    "SC6KMT52CYYG4ALF2LKPZ3JJYUSRDV5ZURLUEWG3MUSBEWXISDMQ7IIM",
    "SC75FSS2VKUPIGMHSQWSPUCYPD42UIO2YHVGAGMPTT6A4KQNNYILVHPX",
    "SCAFXWA7GB2C3R3QAPLS3RZY46IC6ZBZVS6UVVVELKQKBLTS54IL75O6",
    "SCAPFPVBZYVGYWG3JZQND23MOZWRFCCUZK2RUT2ISAGYRTU2JYKV2CE5",
    "SCBFYCI24RBPSXK4TOKS5TZDOVQ3B6OVB5A2I54HXIWVOCFVNFIQRQNJ",
    "SCBITSI6B2PK3HX6Q6UKMUDZGYAMSDDMNB53ZHLRI4PADUUFMHOYA6IP",
    "SCBOE7FNS7IWOV6MLZEFYEEVC6W6NYZ534RAUX27OUNCF6BQAA3SUTG6",
    "SCD34IHXEH6R6XBKGTMFQF5T5R5YBYCEQD5GXS5NJMQ5GIO7QIT5GEZK",
    "SCDA2K3PFGYRV6I3A2M6BB6ELHYC7FQXHIN7NUATBNRDSIXF6LYFDYZF",
    "SCDL4GC7A2U4RN3PB2IRCYDIMRFKZOPTDXEWICY6LK76VKGXPPK3TDVI",
    "SCE2NYYHPSOYNWPCVBGFK3UPPG5JTSM5FNOHH34DKOH7OQTVDJKDRERH",
    "SCE62AHQIBJJB6RDUJG7SESFEU3V5X7EMWN35DGYPGJFQWBF63CV6USN",
    "SCEEXLUUUJEHUOI4OTFRWIA7WP6W5TQIUC6IPMWTVVQBBH56RAYMNNWU",
    "SCEHWZQ4TLD7XH7VNFFR2EZ5AVXL24XVMMXPABGI4VTJX7TJR5B2BBK4",
    "SCEW4VFWIZ7L3KIQKJDHHZFN4JAMNW62ABDMZ2UAIECG6T3Y2PQUK3DI",
    "SCEWQXSMPPXDWFZMQXYUC2Z4QNJCHFEVKARSSM4CIBDVW4KXRWK27VVC",
    "SCFK3CX4GBHJDSE74HXHPMUKY4KKU7OTH7YP356BR6IBS4E55I5TLQ7P",
    "SCFQ4CJP62UUUTZVXBTZ2WXOQ26QA2RZBTAFSNFAIUKBNRTVJSJ4RZIA",
    "SCFRVXDEAFC55QFX2LZ36E25CWFHEOK2W72DT6U625ZV3JAIQGBJLDOA",
    "SCGJIMILTEQ4QKXEMAKN43GRQZOGDFQWLORRTUJIYEVGWNRPMC4EKVGV",
    "SCGXSBDBBD4BM56UU6V4DKF2LM6QKYXATUSHU6O7FSUWL6XWMIAALF33",
    "SCH7TS2BEKG3DU3HHA4HAUASMG3WSSX5YHUXOZTHUYPWBFK6DOG4JAOU",
    "SCHO2FJZONBYN25HQRJXGSJBYWR3PC4QWHN3OTTWOQRMYXN4OOAABQKY",
    "SCHWGXLPY4PRMOMJQ5WVMYK22JXTPFCQRQRNZXLEOCD2JM6PIDIRSJB4",
    "SCI56BPUPYEQ5O6MHEXW6AIMHZ6IHN6V3VQ7YMBCNKPDQRPVFU36HAYQ",
    "SCILLCF7N5IN4ZXIDLPS4FWQBPM6S4Z34LSRCKYOYHXGBOJBGEE5TZWJ",
    "SCIQ7EGHIT5JJEBGCUSRCGANXMGJIUQ75XAKOYYJ5WL2BVQMITR2HQVT",
    "SCIT6BOPIPSJU4FFU6PS6YGLLBN7JN22UCWHEVYV54VKS7BK2K7Q7SGL",
    "SCJL3W6GI6AEWGYWWOSCGLQHEVAA2U6HU6N32ZL2JKWPWGYBY4XVO2OP",
    "SCK4AVGMXS5OMU6X6AGIFN4P4KZODSGX4EL5N33CWLHGWJD547BPRYOL",
    "SCKESCOZNEP5WRJDEYXK3IAPRYDEHR3627SIFAOOO2ICSP2RAUXXIZC2",
    "SCKMHR4N5ZXFZLTWD25WLPDSKXTNNA6VOYUVST7GX54H6NF7OCXPJRTT",
    "SCKRKCRL55JDLQCRWWEWOCY3PJ5O7MJVAH5XTY7CL2JISF2UB27LUBKY",
    "SCLBEBNYVVNWUM2ZI6MRY4NZE76ORHNA6E7KPMSHQMDOZEAVGYSL2XG7",
    "SCLZJGIQIIV5DFXTGIA7DYYQPGVSVVOULJFZGC3KRPIAPB6BZPUORWY4",
    "SCNKMEM2Q6OZIBJSMMEUM77VBJVFXPMOCNJOTCHC7TCRU25FXXLIHMT7",
    "SCNWDMCCRM3OZMBGWZLXGEPY3L3AJCGAQG3WYHGWIYRIGK5VHNBOKXXQ",
    "SCO4M4GHV55UWLQEFBS2SRJLKQM2YNRKFM34OFFKP2WRQQTAZNY3CYQC",
    "SCOA262I5P7LT2ZMTDO6SUJWMFCB3CBOWAMHCCP7RUEZMPERAWZCVCML",
    "SCOHXSK4DISJ5MQKYGTTWKUB3K3AEY5FXLTDRS7WPL4PRX35G4Z4MY22",
    "SCOLKYRERDDT7WBUUOLOJRJYUPZS7UTHJV4K5V5QGUXRVXIKMDNNOASK",
    "SCPGWG5EMUR66KFRYKZRVEECQTFV3X2BCN7TLIVAQWYDONS2SQZSWIJW",
    "SCQ4FRYFU54E3LNZ2COZJRAAEDD7PFM4I7APPXV3IRY5RMMEFEKIXPOT",
    "SCQFOLLRSSFGYH64YGVKX567MNUPK356RTDKMGTW2GASPP7YFKOQG34U",
    "SCQJSYC4ATPLKD65KZ2PMKU5EKRZQMUBN75EMK75GWDEQGFPDQQOFSIW",
    "SCQWJE6AIOFRWZK7UDDNDRHTMF3L4QZ3JYL6WLWK4PFXE3RMF3ORJV5A",
    "SCRXSRMIPB7UHQANTZ2WWQ6EHW7I47ERHFWNODEO5AGIZDTUSHGIGCQM",
    "SCRYEREBIG363QZAECFDZ2DPMHKETLEHRAWBSF46WTB3C4YN3LXQCU4G",
    "SCSBPOFM6HVD43QFPLJS4LF6JBC37GK5Y3ELQXTDAO3L2EHNBDAUMSCL",
    "SCSPHWSZOKKHPONZW34P7B3M4BCUQQVAAGXGOSUY7MWLVBIAI6J57XIL",
    "SCSYYD4LNWQO2XAE3U7CW3K7LJPHNX7MGCBPSJW7IDDQINMB5Z7XQJMQ",
    "SCT536L2YP2LS2HJUN6SB6JS6VGFGPMXPRZIC635VDPMG7XMWGPMTHQS",
    "SCTNNX5VW53DFVYM76BP2UDTA25OPIWVV7GA3633OZLGL77RAQBXSXH7",
    "SCTVH3EMKIA7L2JNQBTBEKZWY7SUE2TAGW7LQQTLWXUVJ5OCG5JQJTN7",
    "SCUCCUPQ5PTOPCBVYY6JPRYRWE5SFACQIWP5ZA2O4OL6EDQPCSIH2LVB",
    "SCVFPBELNVYBVHNDWOBLSZMUQBW7M7YJEP7RZWG7BMGTSGJ2Q56XQT4W",
    "SCXAFM6CXH2KP2H73235FJE7JC5DMQBWBY2OKZHUEFMZ2OBNSKSZOLNL",
    "SCXVCWSHL4PRWVQYXT7UNWWQZMPTJRP5IJEWDOI5366CBTVZ5IFUCXSD",
    "SCYEYFA6QAMTWBUUYCLZL4R6TXU3W4W3ZKJVXTAVPFOGTBRGVL4FBFT7",
    "SCYQOLODJHP4I6A55WP4UG7IGT62BKR7IE2M3HEJLCUVVTYZXVPLSJHS",
    "SCYYBYQFSZ3ZBJB5IKXKVUKQLGOGLV4MVUTP3EDFGDCE74IU52UWXRUQ",
    "SCZOCFX7USH572QH5YONQDNAETORWJ36SH7TPBYBLSXAJRXZ2VQUQZRA",
    "SCZYE5YJHM3KXGSN3S2CDZNB5U5AWBMYST5AIO6YX75UCTNE4JSL235E",
    "SD2T7HMA632MW7O2HFRHZ23RJCNPZQMGYC5O7R6WJYVK6OBV3IABEO6N",
    "SD2Z6LAJ5X6HAUGEQYEEUO3CCEQNRKGY7AYI5YYXCBJTGANNPAKY42D4",
    "SD34HKWUQ444UKNT7NXKU64FXPQWDQ6KR3NRSGRZM36XUE5QUPO6S6AJ",
    "SD4SMAWW7JKWK7CAWFKXO3KTM27B4H4J7CHJI3PZOO3Q6MXWPRC3VLDR",
    "SD4T7CWZVH7CXAW4NLPXRAVS3NVDPGKKM7N2KD6ENQIU3GUYI5CMKPHB",
    "SD5FGKRJ6OIQM72U7FWLNFPQGFSOJY4U2LLVY56KCMTEZITKUBL7ZWHX",
    "SD5HAB23GFOYQYSKFIOX6BEQBOZZJIZ3VJYKCA6G7JY2YLW4IMTAPOX6",
    "SD5QCFUUJDWL5C2K4K2DECLFBLDK3WNXJ4AO35YS4AGMJEOJENH5SSRH",
    "SD5VHNMGIJC2Y6BRVVRAO3IXCEIHFF4PIMNYU7TOX5HY62NUM4XYEELX",
    "SD62EKY3X2YVU43N6M2P244OLYXI4KODG5G3DK6J3QXTEG3GTLIOSYGK",
    "SD64SI5NI6MV25QHGQ76PB74W4LECG2CHRDF6WA3EZUBV6APAI3GHHZK",
    "SD6FBMNFLCOHT5UU4LLYDUU7MKEJVKKDDRGHKARAC27ZCKGJZIBSWXZ5",
    "SD6VSVUU7XVR3DRXESFEEM5ABZK3HPP3OJDPU7CCOVX6L3NED2JQLN6H",
    "SD7HYEPFE4D3SN2HPMZIPIQ4YVRWOFI4BSH4EKQDABGPHWZV6LAIUOMB",
    "SDACTOWJ2ISMDAC5YHWCCDOM7H6PXM3KTQTKYFDJRXUYL5XZ73A2KW7Q",
    "SDAIZOEFXCXNLLYQHHY27Y7OVMRTRDJM67VGH3TFIH3NNNJ5QEBA2KZW",
    "SDAY2PZKOUB27736GONM5JEYAXAN2VRF42QBUNSZ635XDQOMCMV2XHPE",
    "SDBDPLLTG6WNKP7VYDDOKWTJYFWQMWZANCHJ7CUQTGO4CSAKA543TXHD",
    "SDBNLNA6SABJ54PRQ4ICBUWF4HRHCPIP3IGDAUYB2LSK5XM3T5KOOWE5",
    "SDCRKILZYIRYOW7PIPSHGABPX5LNRBFRGAYPQJ4VMNVSRPMSRESZECNM",
    "SDCVQ2PQHUPFITTQZR354WP3LNDMFN6DNJE7IMUKL5SQ3PUJMTL36YX3",
    "SDF2V46YSZEHWZEPXE3CRXCMBM3VW44RSW2CQYSTUPEOI6TREPQAMNHA",
    "SDFCLVCASEDNSVB22EYYLM6YBY2HSE4RSDHOWDLNB5DHZTQ3L44IB3UK",
    "SDFKU4VURXK5ZXFGB6Q4TAHXVU664OHILCAOGHJZ7AQCN6YDFYBQ54XT",
    "SDI6HPUGJSLKE4DI3STVCB44HBCKQQIP7UNGZAU2U46GDF2SXPWENJVM",
    "SDIIWYYQQO2SBLYQX4LOKTFFEHRT2UKYWGARC4F6MQADGNTRFUYCO7BR",
    "SDJ5Q36R36A267MRPFX2S6DKO74C6BD5JTPP33ZLLVVNVDN2K7UDMW26",
    "SDJ6FXWJEAZQTKMJIEXB7FY4Q2LRMA7N6E7TBDHPPORXDYHDBX5LLU6T",
    "SDJ6TOHCKE3XOQMQMWFXYDT33ITGCP64KGAC7K3VUM75EPLGJIZ5YV4Y",
    "SDJISWS5IC77TJYZGC7BLUOWUGU7265EOLZO6TTDPGI3PBHM7E7Y7GHQ",
    "SDJO2OI377D6IFPRBO2H54GP5XPMJZL76RCQDIHVPQVGGIAZ3WCEM2X6",
    "SDKWY3XL5EUYVZZ5OUQMPLUZ5ROAYFSUMHCH3IR43YA7J7PARJHZMABO",
    "SDMQQZ2NCD3Z25YDJUJWJEJRTZDJKQLHCDPUXLTOSJPHR7SAWG5BPKTD",
    "SDO3CA5HEA4TGMYDSLFNYEVFNQG2QNWFZ5WF27QD3ULUYB6YVBPKCSZV",
    "SDOC5FGC4AHXI4RAQ7YC72FEVCCA6ZXYM5K6JWTAMNKNVSZJRXWZUP4P",
    "SDOI4PY5NJHODVIBN4QXSQRCCFJDSR3CRDI4TXEYAJ3JV3ETXSBB6H3Y",
    "SDOWUPERE7BCHV5UUSKRRAVKQNF7XT4JNW6UA2V2IC767VWCRSLG2TM5",
    "SDPIVKQXS3YGDQB7QBXFSAQKZVDCXR7MFAP52XLZ22EPSCMQZMSQLEE3",
    "SDPRUJASVC5FLQYI6UYDZ2KQ3VTULMD57QVNOO7O3LXPXEJSKGIW7LMI",
    "SDQGSJKPOZY4QOHGBHWK7AERRLBLA76KL6HFDR4TV2JR5QZLL32HO6K7",
    "SDT27UBVZULNOJXRHIPFTDORQ7DVLCNMTV2M6VSENZY4WH2S5DBGVEYQ",
    "SDTAPOTSIQHH2R4PS7FPJB5K4RNFYXPV5NSKMITR2XPMBF532G6DS2M2",
    "SDTFEIECJFEH7QA6CUAREJW3Z47447E2MGXCLUBFPHNT6LHDEXGRPA2J",
    "SDTH4PZ4XZVEOQTYUBTYY673Z7FHLFJAOABBBVMO542Q3N5AYG3OQTJQ",
    "SDTITWCDJYMHTJGLUOQQPZLPFCVRMXXXSI7T42FUORLGW2FHBKMPHRNK",
    "SDU3YIULAKJCAFCJ5WDJFZGETNLCFGQVDD7XRFALGVQPPRNFE7GTBICG",
    "SDUPC6RN67VRRO6GALWPZVW76ZB3GQXKUY3INHHZXCYOW5ONCMW6VMNK",
    "SDUSPZP4PHF7HHWFJH5YARFNTNQVQR5FQNNVS5QZ4BDQYHMRTSZN7WKH",
    "SDUTOMO4CEFHNM5ULUEAS7JJELYPDEXU4XMQJ5HXM3FFLNWNN4JOVQTZ",
    "SDV3KL4SEFV4LON2SXTIWV5IHGPYRSHUHURVWYLO7XUQLJTVINWUXGFG",
    "SDVBQB747PDRKYPLR6T7D4ULQALXPOWK2HJ5APQVMQPHONN4MF53HRQX",
    "SDVUTPLRESMBMJDFU3LJMXX4O2PXSD5CHJHV3GBVZFBDKNWERCXJZXFG",
    "SDWIMF2JT66UQ7PX2TIEAAZYNTWUGHSXTPRJOKTQQM5W4KFAUFIICPUE",
    "SDWJFIP54UELTR5FC3FQ5NYBUYVUTV5W7UQCFJXOTG4RYEGKLSUMRLDH",
    "SDWW7GBLCYOHXRJGT66VPGGM3RV2R4O5ELZZRALFNT3EKHVABHPHRQEL",
    "SDXFYEKPERGQMAKLHJENXPMU4FOAVRHSVKNRMJ53NYIRLR4ARENF2UD6",
    "SDXQH4ECVEAQUNA7C5XKGMNZCECNVMKONPT2M3XRRYTTVYNV6ZAMPHU7",
    "SDYOAFA2CW5XYT3NLWIJELMWKT7FBPGFTQG4YMZQ5C66I7FBF36X27BE",
    "SDYRDP5I52KS5WOKF2CEAS5RMHO5AYYMIX6CTOMUWY3YUMTJLEKRER2O",
];
