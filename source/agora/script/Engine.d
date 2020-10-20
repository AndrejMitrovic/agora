/*******************************************************************************

    Contains the script execution engine (non-webASM)

    Copyright:
        Copyright (c) 2020 BOS Platform Foundation Korea
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.script.Engine;

import agora.script.Codes;

/// The engine executes scripts, and returns a value or throws
public class Engine
{
    public void execute (Script lock, Script unlock)
    {
        this.executeScript(unlock);
    }
}
