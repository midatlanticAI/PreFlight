// XL-001 / JV-DESERIALIZE-001 positive fixture.
// Reading a Java object graph straight off an untrusted socket stream.
public class Handler {
    Object handle(java.net.Socket socket) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        return ois.readObject();
    }
}
