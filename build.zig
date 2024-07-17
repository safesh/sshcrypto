const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("ssh-certs", .{
        .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = b.pathFromRoot("src/mod.zig") } },
        .target = target,
        .optimize = optimize,
    });

    const unit_test = b.addTest(.{
        .root_source_file = b.path("src/mod.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_test).step);
}
