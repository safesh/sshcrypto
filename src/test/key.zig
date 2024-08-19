const std = @import("std");

test "a" {
    const public = @embedFile("rsa-key.pub");

    const private = @embedFile("rsa-key");

    std.debug.print("public key: {s}", .{public});
    std.debug.print("private key: {s}", .{private});
}
