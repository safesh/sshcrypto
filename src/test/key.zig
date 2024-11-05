const std = @import("std");

const sshcrypto = @import("sshcrypto");

const expect = std.testing.expect;
const expect_eql = std.testing.expectEqual;

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

    const key = try sshcrypto.key.private.RSA.from(pem.data.der);

    _ = try sshcrypto.key.public.RSA.from_bytes(key.public_key_blob);
    const private_key = try key.get_key(std.testing.allocator, null);

    try expect_eql(
        @as(u32, @truncate(private_key.checksum >> @bitSizeOf(u32))),
        @as(u32, @truncate(private_key.checksum)),
    );
    try expect(std.mem.eql(u8, private_key.kind, "ssh-rsa"));
}

// test "rsa private key with passphrase" {
//     const pem = try key_decoder.decode(@embedFile("rsa-key-123"));
//     defer pem.deinit();
//
//     const key = try sshcrypto.key.private.RSA.from(pem.data.der);
//
//     _ = try key.get_key(std.testing.allocator, "123");
//
//     std.debug.print("{s}\n", .{key.cipher.name});
//     std.debug.print("{any}\n", .{key.kdf});
// }

// test "supported chipers" {
//     for (sshcrypto.key.private.Cipher.get_supported_ciphers()) |cipher| {
//         std.debug.print("{s}\n", .{cipher});
//     }
// }
