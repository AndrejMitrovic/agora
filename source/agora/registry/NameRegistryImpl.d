/*******************************************************************************

    Definitions of the name registry API Implementation

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.registry.NameRegistryImpl;

import agora.common.Hash;
import agora.common.Types;
import agora.common.crypto.Key;
import agora.registry.NameRegistryAPI;
import agora.utils.Log;

import vibe.core.core;
import vibe.http.common;
import vibe.web.rest;

mixin AddLogger!();

/// Implementation of `NameRegistryAPI` using associative arrays
static class NameRegistryImpl: NameRegistryAPI
{

    ///
    private RegistryPayloadData[PublicKey] registry_map;

    /***************************************************************************

        Get network addresses corresponding to a public key

        Params:
            public_key = the public key that was used to register
                         the network addresses

        Returns:
            Network addresses associated with the `public_key`

        API:
            GET /network_addresses

    ***************************************************************************/

    public override Address[] getNetworkAddresses (PublicKey public_key)
    {
        if(public_key in registry_map)
            return registry_map[public_key].addresses;
        else
            return [];
    }

    /***************************************************************************

        Register network addresses corresponding to a public key

        Params:
            registry_payload =
                the data we want to register with the name registry server

        Returns:
            empty string, if the registration was successful, otherwise returns
            the error message

        API:
            PUT /register_network_addresses

    ***************************************************************************/

    public override string registerNetworkAddresses (RegistryPayload registry_payload)
    {
        // verify signature
        if (!registry_payload.data.public_key.verify(registry_payload.signature, hashFull(registry_payload.data)[]))
            return "incorrect signature";

        // check if we received stale data
        if ((registry_payload.data.public_key in registry_map) &&
             registry_map[registry_payload.data.public_key].seq > registry_payload.data.seq)
            return "registry already has a more up-to-date version of the data";

        // register data
        log.info("Registering network addresses: {} for public key: {}", registry_payload.data.addresses,
            registry_payload.data.public_key.toString());
        registry_map[registry_payload.data.public_key] = registry_payload.data;
        return "";
    }
}
