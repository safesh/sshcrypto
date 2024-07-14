const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("ssh-certs", .{
        .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = b.pathFromRoot("src/mod.zig") } },
        .target = target,
        .optimize = optimize,
    });
}
