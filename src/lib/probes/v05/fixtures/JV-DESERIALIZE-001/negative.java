// XL-001 / JV-DESERIALIZE-001 negative fixture.
// JSON binding to a concrete type, no default typing, no readObject.
public class Handler {
    Config handle(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Config.class);
    }
}
