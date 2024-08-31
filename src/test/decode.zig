const std = @import("std");

const sshcrypt = @import("sshcrypto");
const sshkey = sshcrypt.key;

const Decoder = sshcrypt.Decoder(sshkey.Pem);

test "decode in place" {
    const rodata = @embedFile("rsa-key.pub");

    const key = try std.testing.allocator.alloc(u8, rodata.len);
    defer std.testing.allocator.free(key);

    std.mem.copyForwards(u8, key, rodata);

    _ = try Decoder.decode_in_place(
        std.base64.standard.Decoder,
        key,
    );
}

test "decode with allocator" {
    const decoder = Decoder.init(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );

    const pem = try decoder.decode(@embedFile("rsa-key.pub"));
    defer pem.deinit();
}
