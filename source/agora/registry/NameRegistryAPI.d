/*******************************************************************************

    Definitions of the name registry API

    Copyright:
        Copyright (c) 2019-2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.registry.NameRegistryAPI;

import agora.common.Hash;
import agora.common.Types;
import agora.common.crypto.Key;

import vibe.http.common;
import vibe.web.rest;

///
struct RegistryPayloadData
{
    /// the public key that we want to register
    public PublicKey public_key;

    /// network addresses associated with the public key
    public const(Address)[] addresses;

    /// monotonically increasing sequence number
    public long seq;
}

///
struct RegistryPayload
{
    ///
    public RegistryPayloadData data;

    /// signature over the `data` member
    public Signature signature;

    ///
    public void sign_payload(const ref SecretKey secret_key) nothrow
    {
        signature = secret_key.sign(hashFull(data)[]);
    }
};

/// API allowing to store network addresses under a public key
static interface NameRegistryAPI
{
    @safe:

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

    public const(Address)[] getNetworkAddresses (PublicKey public_key);

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

    @method(HTTPMethod.PUT)
    public string registerNetworkAddresses (RegistryPayload registry_payload);

}
