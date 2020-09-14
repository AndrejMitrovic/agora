/*******************************************************************************

    Definitions of the name registry client

    This client is a thin wrapper around the `NameRegistryApi`

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.registry.NameRegistryClient;

import agora.common.Hash;
import agora.common.Types;
import agora.common.crypto.Key;
import agora.registry.NameRegistryAPI;

import core.stdc.time;

/// Thin wrapper around `NameRegistryApi`
class NameRegistryClient
{
    private NameRegistryAPI registryAPI;

    public this (NameRegistryAPI registryAPI)
    {
        this.registryAPI = registryAPI;
    }

    /***************************************************************************

        Get network addresses corresponding to a public key

        Params:
            public_key = the public key that was used to register
                         the network addresses

        Returns:
            Network addresses associated with the `public_key`

    ***************************************************************************/

    public Address[] getNetworkAddresses (const ref PublicKey public_key)
    {
        return registryAPI.getNetworkAddresses(public_key);
    }

    /***************************************************************************

        Register network addresses corresponding to a public key

        Params:
            key_pair = asymmetric key pair
            addresses = addresses that needs to be registered

        Returns:
            empty string, if the registration was successful, otherwise returns
            the error message

    ***************************************************************************/

    public string registerNetworkAddresses (immutable ref KeyPair key_pair, Address[] addresses)
    {
        RegistryPayload registry_payload =
        {
            data:
            {
                public_key : key_pair.address,
                addresses : addresses,
                seq : time(null)
            }
        };
        registry_payload.sign_payload(key_pair.secret);

        return registryAPI.registerNetworkAddresses(registry_payload);
    }
}
