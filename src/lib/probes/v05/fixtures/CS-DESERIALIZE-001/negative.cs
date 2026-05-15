// XL-001 / CS-DESERIALIZE-001 negative fixture.
// System.Text.Json to a concrete type; no dangerous formatter, no default typing.
public class Loader {
    public Config Load(string json) {
        return System.Text.Json.JsonSerializer.Deserialize<Config>(json);
    }
}
