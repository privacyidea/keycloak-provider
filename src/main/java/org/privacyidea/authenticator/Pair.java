package org.privacyidea.authenticator;

import org.privacyidea.PrivacyIDEA;

public class Pair
{
    private PrivacyIDEA privacyIDEA;
    private Configuration configuration;

    public Pair(PrivacyIDEA privacyIDEA, Configuration configuration)
    {
        this.privacyIDEA = privacyIDEA;
        this.configuration = configuration;
    }

    public PrivacyIDEA privacyIDEA()
    {
        return privacyIDEA;
    }

    public Configuration configuration()
    {
        return configuration;
    }
}
