/*
 * Copyright 2023 NetKnights GmbH
 * nils.behlen@netknights.it
 * <p>
 * Based on original code:
 * <p>
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.privacyidea.authenticator;

import org.privacyidea.PrivacyIDEA;

public class Pair
{
    private final PrivacyIDEA privacyIDEA;
    private final Configuration configuration;

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