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
    const run_test = b.addRunArtifact(unit_test);

    test_step.dependOn(&run_test.step);

    const emit_docs = b.addSystemCommand(&.{
        "zig",
        "test",
        "src/mod.zig",
        "-femit-docs",
        "-fno-emit-bin",
    });

    const docs_step = b.step("docs", "Build documentation");
    docs_step.dependOn(&emit_docs.step);

    const perf = b.addTest(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_perf = b.addSystemCommand(&.{
        "perf",
        "record",
        "-e",
        "cache-references,cache-misses,cycles,instructions,branches,faults,migrations",
    });

    run_perf.has_side_effects = true;
    run_perf.addArtifactArg(perf);

    const perf_step = b.step("perf", "Perf record");
    perf_step.dependOn(&run_perf.step);

    const run_debug = b.addSystemCommand(&.{"gdb"});

    const debug_step = b.step("debug", "Run test target with gdb");
    debug_step.dependOn(&run_debug.step);
}
