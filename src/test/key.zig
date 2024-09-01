const std = @import("std");

const sshcrypto = @import("sshcrypto");
const pubk = sshcrypto.key.Public;

const Decoder = sshcrypto.Decoder(pubk.Pem);

test "rsa public key" {
    const pem = try Decoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("rsa-key.pub"));
    defer pem.deinit();

    _ = try pubk.RSA.from_bytes(pem.data.der);
}

test "ecdsa public key" {
    const pem = try Decoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("ecdsa-key.pub"));
    defer pem.deinit();

    _ = try pubk.ECDSA.from_bytes(pem.data.der);
}

test "ed25519 public key" {
    const pem = try Decoder
        .init(std.testing.allocator, std.base64.standard.Decoder)
        .decode(@embedFile("ed25519-key.pub"));
    defer pem.deinit();

    _ = try pubk.ED25519.from_bytes(pem.data.der);
}
