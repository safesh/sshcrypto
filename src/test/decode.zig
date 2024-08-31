const sshk = @import("sshkeys");
const std = @import("std");

const sshkey = sshk.key;

test "decode in place" {
    const rodata = @embedFile("rsa-key.pub");

    const key = try std.testing.allocator.alloc(u8, rodata.len);
    defer std.testing.allocator.free(key);

    std.mem.copyForwards(u8, key, rodata);

    const decoder = sshk.Decoder(sshkey.Pem);

    _ = try decoder.decode_in_place(
        std.base64.standard.Decoder,
        key,
    );
}

test "decode with allocator" {
    const decoder = sshk.Decoder(sshk.key.Pem).init(
        std.testing.allocator,
        std.base64.standard.Decoder,
    );

    const pem = try decoder.decode(@embedFile("rsa-key.pub"));
    defer pem.deinit();
}
