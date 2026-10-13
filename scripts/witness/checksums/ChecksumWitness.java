// java.util.zip's checksums: crc32 (CRC32), crc32c (CRC32C) and adler32
// (Adler32). One
// request per line on stdin, "NAME PATH", answered with the checksum of
// the file's bytes as lowercase big endian hex, or "error". The data goes
// in in pieces of 1, 2, 3 ... bytes.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

public class ChecksumWitness {
    static Checksum named(String name) {
        switch (name) {
            case "crc32": return new CRC32();
            case "crc32c": return new CRC32C();
            case "adler32": return new Adler32();
            default: return null;
        }
    }

    public static void main(String[] args) throws Exception {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = in.readLine()) != null) {
            String[] parts = line.trim().split("\\s+");
            Checksum c = parts.length == 2 ? named(parts[0]) : null;
            byte[] data;
            try {
                data = c == null ? null : Files.readAllBytes(Paths.get(parts[1]));
            } catch (Exception e) {
                data = null;
            }
            if (data == null) {
                System.out.println("error");
                continue;
            }
            for (int at = 0, step = 1; at < data.length; at += step, step++) {
                c.update(data, at, Math.min(step, data.length - at));
            }
            System.out.println(String.format("%08x", c.getValue()));
        }
    }
}
