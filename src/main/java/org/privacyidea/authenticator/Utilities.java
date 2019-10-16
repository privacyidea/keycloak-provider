package org.privacyidea.authenticator;

import javax.json.*;
import javax.json.stream.JsonGenerator;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class Utilities {

    private Configuration _config;

    public Utilities(Configuration config) {
        this._config = config;
    }

    static String prettyPrintJson(String json) {
        StringWriter sw = new StringWriter();
        try {
            JsonReader jr = Json.createReader(new StringReader(json));
            JsonObject jobj = jr.readObject();

            Map<String, Object> properties = new HashMap<>(1);
            properties.put(JsonGenerator.PRETTY_PRINTING, true);

            JsonWriterFactory writerFactory = Json.createWriterFactory(properties);
            JsonWriter jsonWriter = writerFactory.createWriter(sw);

            jsonWriter.writeObject(jobj);
            jsonWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sw.toString();
    }

    static String buildPromptMessage(List<String> messages, String defaultMessage) {
        String res = defaultMessage;
        if (messages.size() > 1) {
            res = messages.remove(0);
            res += messages.stream().reduce("", (a, s) -> a += " or " + s);
        } else if (messages.size() == 1) {
            res = messages.get(0);
        }
        return res;
    }
}
