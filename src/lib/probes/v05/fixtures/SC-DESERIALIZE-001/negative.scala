// XL-001 / SC-DESERIALIZE-001 negative fixture.
// Type-safe JSON decoding with circe; no JVM serialization.
object Loader {
  def load(json: String): Either[io.circe.Error, Config] =
    io.circe.parser.decode[Config](json)
}
