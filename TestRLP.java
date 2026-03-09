import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.rlp.RLP;

public class TestRLP {
    public static void main(String[] args) {
        int ethVersion = 68;
        long networkId = 1;
        Bytes32 genesisHash = Bytes32.fromHexString("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
        byte[] forkIdHash = new byte[]{(byte) 0x07, (byte) 0xc9, (byte) 0x46, (byte) 0x2e};
        long forkNext = 0;
        Bytes DEFAULT_TOTAL_DIFFICULTY = Bytes.fromHexString("0x400000000000000000");

        byte[] payload = RLP.encodeList(writer -> {
            writer.writeInt(ethVersion);
            writer.writeLong(networkId);
            writer.writeValue(DEFAULT_TOTAL_DIFFICULTY);
            writer.writeValue(genesisHash);
            writer.writeValue(genesisHash);
            writer.writeList(forkWriter -> {
                forkWriter.writeValue(Bytes.wrap(forkIdHash));
                forkWriter.writeLong(forkNext);
            });
        }).toArrayUnsafe();

        System.out.println("Length: " + payload.length);
        StringBuilder sb = new StringBuilder();
        for (byte b : payload) sb.append(String.format("%02x", b));
        System.out.println("Hex: " + sb.toString());
    }
}
