// XL-001 / CS-DESERIALIZE-001 positive fixture.
// BinaryFormatter.Deserialize is an obsolete .NET RCE vector.
public class Loader {
    public object Load(System.IO.Stream stream) {
        var fmt = new BinaryFormatter();
        return fmt.Deserialize(stream);
    }
}
