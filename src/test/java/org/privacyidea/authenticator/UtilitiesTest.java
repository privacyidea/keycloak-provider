package org.privacyidea.authenticator;

import org.junit.Assert;
import org.junit.Test;
import java.util.ArrayList;
import org.privacyidea.authenticator.Utilities;

public class UtilitiesTest {

    @Test
    public void buildPromptMessageDefault() {
        final ArrayList<String> strings = new ArrayList<String>();
        final String ret = Utilities.buildPromptMessage(strings, "Hello World!");
        Assert.assertEquals("Hello World!", ret);
    }

    @Test
    public void buildPromptMessageSingleString() {
        final ArrayList<String> strings = new ArrayList<String>();
        strings.add("Hello World!");
        final String ret = Utilities.buildPromptMessage(strings, "Default");
        Assert.assertEquals("Hello World!", ret);
    }

    @Test
    public void buildPromptMessageMultipleStrings() {
        final ArrayList<String> strings = new ArrayList<String>();
        strings.add("Hello");
        strings.add("World!");
        final String ret = Utilities.buildPromptMessage(strings, "Default");
        Assert.assertEquals("Hello or World!", ret);
    }
}
