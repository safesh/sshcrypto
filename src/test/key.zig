const std = @import("std");

const sshcrypto = @import("sshcrypto");

const pub_key_decoder = sshcrypto.pem.PublicKeyDecoder
    .init(std.testing.allocator, std.base64.standard.Decoder);

test "Rsa public key" {
    const pem = try pub_key_decoder.decode(@embedFile("rsa-key.pub"));
    defer pem.deinit();

    _ = try sshcrypto.key.public.RSA.from_pem(pem.data);
    // TODO: Check fields
}

test "Ecdsa public key" {
    const pem = try pub_key_decoder.decode(@embedFile("ecdsa-key.pub"));
    defer pem.deinit();

    _ = try sshcrypto.key.public.ECDSA.from_pem(pem.data);
    // TODO: Check fields
}

test "ed25519 public key" {
    const pem = try pub_key_decoder.decode(@embedFile("ed25519-key.pub"));
    defer pem.deinit();

    _ = try sshcrypto.key.public.ED25519.from_pem(pem.data);
    // TODO: Check fields
}

const key_decoder = sshcrypto.pem.PrivateKeyDecoder
    .init(std.testing.allocator, sshcrypto.base64.pem.Decoder);

test "Rsa private key: get_public_key" {
    const pem = try key_decoder.decode(@embedFile("rsa-key"));
    defer pem.deinit();

    const private_key = try sshcrypto.key.private.Rsa.from_pem(pem.data);

    _ = try private_key.get_public_key();
    // TODO: Check fields
}
test "Rsa private key: get_private_key" {
    const pem = try key_decoder.decode(@embedFile("rsa-key"));
    defer pem.deinit();

    const key = try sshcrypto.key.private.Rsa.from_pem(pem.data);

    const private_key = try key.get_private_key(std.testing.allocator, null);

    try std.testing.expectEqualSlices(u8, private_key.data.kind, "ssh-rsa");
    try std.testing.expectEqualSlices(u8, private_key.data.comment, "root@locahost"); // FIXME: Fix typo

    // TODO: Check other fields
}

test "rsa private key with passphrase" {
    const pem = try key_decoder.decode(@embedFile("rsa-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.private.Rsa.from_pem(pem.data);

    var private_key = try key.get_private_key(std.testing.allocator, "123");
    defer private_key.deinit();

    try std.testing.expect(private_key.data._pad.verify());

    try std.testing.expectEqualSlices(u8, private_key.data.kind, "ssh-rsa");
    try std.testing.expectEqualSlices(u8, private_key.data.comment, "root@locahost"); // FIXME: Fix typo
    // TODO: Check other fields
}

test "Ed25519 private key: get_private_key" {
    const pem = try key_decoder.decode(@embedFile("ed25519-key"));
    defer pem.deinit();

    const key = try sshcrypto.key.private.Ed25519.from_pem(pem.data);

    const private_key = try key.get_private_key(std.testing.allocator, null);

    try std.testing.expectEqualSlices(u8, private_key.data.kind, "ssh-ed25519");
    try std.testing.expectEqualSlices(u8, private_key.data.comment, "root@locahost");
    // TODO: check other fields
}

test "Ed25519 private key with passphrase: get_public_key" {
    const pem = try key_decoder.decode(@embedFile("ed25519-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.private.Ed25519.from_pem(pem.data);

    _ = try key.get_public_key();
}

test "Ed25519 private key with passphrase: get_private_key" {
    const pem = try key_decoder.decode(@embedFile("ed25519-key-123"));
    defer pem.deinit();

    const key = try sshcrypto.key.private.Ed25519.from_pem(pem.data);

    var private_key = try key.get_private_key(std.testing.allocator, "123");
    defer private_key.deinit();

    try std.testing.expectEqualSlices(u8, private_key.data.kind, "ssh-ed25519");
    try std.testing.expectEqualSlices(u8, private_key.data.comment, "root@localhost");
}

test "ed25519 public key with long comment" {
    const pem = try pub_key_decoder.decode(@embedFile("ed25519-key-long-comment.pub"));
    defer pem.deinit();

    const expected = "This is a long comment with spaces in between, OpenSSH really does allow anything here...";

    try std.testing.expectEqualSlices(u8, expected, pem.data.comment.val);
}

test "ed25519 private key with long comment" {
    const pem = try key_decoder.decode(@embedFile("ed25519-key-long-comment"));
    defer pem.deinit();

    const key = try sshcrypto.key.private.Ed25519.from_pem(pem.data);

    const private_key = try key.get_private_key(std.testing.allocator, null);

    const expected = "This is a long comment with spaces in between, OpenSSH really does allow anything here...";

    try std.testing.expectEqualSlices(u8, expected, private_key.data.comment);
}

// test "supported chipers" {
//     for (sshcrypto.key.private.Cipher.get_supported_ciphers()) |cipher| {
//         std.debug.print("{s}\n", .{cipher});
//     }
// }
