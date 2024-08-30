const std = @import("std");

const panic = std.debug.panic;

const ArrayList = std.ArrayList;
const Tuple = std.meta.Tuple;

const Allocator = std.mem.Allocator;

const PERF_EVENTS: []const u8 = "cache-references,cache-misses,cycles,instructions,branches,faults,migrations";

const TEST_CERTS_PATH: []const u8 = "tools/certs/";
const TEST_KEYS_PATH: []const u8 = "tools/keys/";

const TestAssets = ArrayList(Tuple(&.{ []u8, []u8 }));

// TODO: Make this comptime
fn get_test_assets(allocator: std.mem.Allocator, path: []const u8) !TestAssets {
    var ret = ArrayList(Tuple(&.{ []u8, []u8 })).init(allocator);

    var assets = try std.fs.cwd().openDir(path, .{ .iterate = true });
    defer assets.close();

    var walker = try assets.walk(allocator);

    while (try walker.next()) |entry| {
        if (std.mem.endsWith(u8, ".sh", entry.basename)) continue;

        const basename = entry.basename[0..entry.basename.len];

        try ret.append(.{
            // This is fine for this use-case
            try allocator.dupe(u8, basename), // name
            try std.mem.concat(allocator, u8, &.{ // path
                path,
                basename,
            }),
        });
    }

    return ret;
}

const Test = struct {
    root_source_file: std.Build.LazyPath,

    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,

    mod: ?*std.Build.Module,
    mod_name: ?[]const u8,

    assets: ?*const TestAssets,
};

fn add_test(b: *std.Build, step: *std.Build.Step, t: Test) !void {
    const test_case = b.addTest(.{
        .root_source_file = t.root_source_file,
        .target = t.target,
        .optimize = t.optimize,
    });

    if (t.mod) |mod|
        test_case.root_module.addImport(t.mod_name.?, mod);

    if (t.assets) |assets| for (assets.items) |cert| {
        const name, const file = cert;
        test_case.root_module.addAnonymousImport(
            name,
            .{ .root_source_file = b.path(file) },
        );
    };

    const run_test_case = b.addRunArtifact(test_case);

    step.dependOn(&run_test_case.step);
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("sshkeys", .{
        .root_source_file = .{
            .src_path = .{
                .owner = b,
                .sub_path = b.pathFromRoot("src/sshkeys.zig"),
            },
        },
        .target = target,
        .optimize = optimize,
    });

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    arena.deinit();

    const certs = get_test_assets(arena.allocator(), TEST_CERTS_PATH) catch
        @panic("Fail to get test certs assets");

    const keys = get_test_assets(arena.allocator(), TEST_KEYS_PATH) catch
        @panic("Fail to get test keys assets");

    const test_step = b.step("test", "Run unit tests");
    {
        add_test(b, test_step, .{
            .root_source_file = b.path("src/test/cert.zig"),
            .target = target,
            .optimize = optimize,
            .mod = mod,
            .mod_name = "sshkeys",
            .assets = &certs,
        }) catch @panic("OOM");

        add_test(b, test_step, .{
            .root_source_file = b.path("src/test/key.zig"),
            .target = target,
            .optimize = optimize,
            .mod = mod,
            .mod_name = "sshkeys",
            .assets = &keys,
        }) catch @panic("OOM");

        add_test(b, test_step, .{
            .root_source_file = b.path("src/test/decode.zig"),
            .target = target,
            .optimize = optimize,
            .mod = mod,
            .mod_name = "sshkeys",
            .assets = &keys,
        }) catch @panic("OOM");
    }

    const docs_step = b.step("docs", "Build documentation");
    {
        const docs_obj = b.addObject(.{
            .name = "sshkeys",
            .root_source_file = b.path("src/sshkeys.zig"),
            .target = target,
            .optimize = optimize,
        });

        const install_docs = b.addInstallDirectory(.{
            .install_dir = .prefix,
            .install_subdir = "docs",
            .source_dir = docs_obj.getEmittedDocs(),
        });

        docs_step.dependOn(&docs_obj.step);
        docs_step.dependOn(&install_docs.step);
    }

    const perf_step = b.step("perf", "Perf record");
    {
        const perf_test = b.addTest(.{
            .root_source_file = b.path("src/perf/cert.zig"),
            .target = target,
            .optimize = optimize,
        });

        perf_test.root_module.addImport("sshkeys", mod);

        for (certs.items) |cert| {
            const name, const file = cert;
            perf_test.root_module.addAnonymousImport(
                name,
                .{ .root_source_file = b.path(file) },
            );
        }

        const run_perf = b.addSystemCommand(&.{ "perf", "record", "-e", PERF_EVENTS });

        run_perf.has_side_effects = true;
        run_perf.addArtifactArg(perf_test);

        perf_step.dependOn(&run_perf.step);
    }

    const debug_step = b.step("debug", "Run test target with gdb");
    {
        const run_debug = b.addSystemCommand(&.{"gdb"});

        debug_step.dependOn(&run_debug.step);
    }
}
