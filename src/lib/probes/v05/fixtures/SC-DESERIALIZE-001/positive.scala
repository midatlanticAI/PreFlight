// XL-001 / SC-DESERIALIZE-001 positive fixture.
// JVM object deserialization from an untrusted stream.
object Loader {
  def load(in: java.io.InputStream): AnyRef =
    new java.io.ObjectInputStream(in).readObject()
}
