/*******************************************************************************

    Defines the data used when reaching consensus.

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.consensus.data.ConsensusData;

import agora.common.Set;
import agora.consensus.data.Enrollment;
import agora.consensus.data.Transaction;

/// Consensus data which is nominated & voted on
public struct ConsensusData
{
    /// The transaction set that is being nominated / voted on
    public Set!Transaction tx_set;

    /// The enrollments that are being nominated / voted on
    public Enrollment[] enrolls;
}
