const std = @import("std");

const sshkey = @import("sshkeys").key;

test "decode public key" {
    var der = try sshkey.PemDecoder.init(
        std.testing.allocator,
        std.base64.standard.Decoder,
    ).decode(@embedFile("rsa-key.pub"));

    defer der.deinit();

    std.debug.print("{s}\n{s}\n{s}", .{ der.magic, der.ref, der.comment });
}
