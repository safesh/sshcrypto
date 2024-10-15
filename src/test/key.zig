const std = @import("std");

const sshcrypto = @import("sshcrypto");

const pub_key_decoder = sshcrypto.pem.PublicKeyDecoder
    .init(std.testing.allocator, std.base64.standard.Decoder);

test "rsa public key" {
    const pem = try pub_key_decoder.decode(@embedFile("rsa-key.pub"));
    defer pem.deinit();

    _ = try sshcrypto.key.public.RSA.from_bytes(pem.data.der);
}

test "ecdsa public key" {
    const pem = try pub_key_decoder.decode(@embedFile("ecdsa-key.pub"));
    defer pem.deinit();

    _ = try sshcrypto.key.public.ECDSA.from_bytes(pem.data.der);
}

test "ed25519 public key" {
    const pem = try pub_key_decoder.decode(@embedFile("ed25519-key.pub"));
    defer pem.deinit();

    _ = try sshcrypto.key.public.ED25519.from_bytes(pem.data.der);
}

const key_decoder = sshcrypto.pem.PrivateKeyDecoder
    .init(std.testing.allocator, sshcrypto.base64.pem.Decoder);

test "rsa private key" {
    const pem = try key_decoder.decode(@embedFile("rsa-key"));
    defer pem.deinit();

    _ = try sshcrypto.key.private.RSA.from(pem.data.der);
}
