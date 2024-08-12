const std = @import("std");

const panic = std.debug.panic;

const ArrayList = std.ArrayList;
const Tuple = std.meta.Tuple;

const Allocator = std.mem.Allocator;

const PERF_EVENTS: []const u8 = "cache-references,cache-misses,cycles,instructions,branches,faults,migrations";
const TEST_CERTS_PATH: []const u8 = "tools/certs/";

// TODO: Make this comptime
fn get_test_certs(allocator: std.mem.Allocator) !ArrayList(Tuple(&.{ []u8, []u8 })) {
    var ret = ArrayList(Tuple(&.{ []u8, []u8 })).init(allocator);
    errdefer ret.deinit();

    var certs = try std.fs.cwd().openDir("tools/certs", .{ .iterate = true });
    defer certs.close();

    var walker = try certs.walk(allocator);
    defer walker.deinit();

    while (try walker.next()) |entry|
        if (std.mem.endsWith(u8, entry.basename, ".pub")) {
            const basename = entry.basename[0..entry.basename.len];

            // This is fine for this usecase
            const name = try allocator.dupe(u8, basename);
            const path = try std.mem.concat(allocator, u8, &.{
                TEST_CERTS_PATH,
                basename,
            });

            try ret.append(.{ name, path });
        };

    return ret;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("sshkeys", .{
        .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = b.pathFromRoot("src/cert.zig") } },
        .target = target,
        .optimize = optimize,
    });

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    arena.deinit();

    const certs = get_test_certs(arena.allocator()) catch |err|
        panic("{}", .{err});
    defer certs.deinit();

    const test_step = b.step("test", "Run unit tests");
    {
        const unit_test = b.addTest(.{
            .root_source_file = b.path("src/test/cert.zig"),
            .target = target,
            .optimize = optimize,
        });

        unit_test.root_module.addImport("sshkeys", mod);

        for (certs.items) |cert| {
            const name, const file = cert;
            unit_test.root_module.addAnonymousImport(
                name,
                .{ .root_source_file = b.path(file) },
            );
        }

        const run_test = b.addRunArtifact(unit_test);

        test_step.dependOn(&run_test.step);
    }

    const docs_step = b.step("docs", "Build documentation");
    {
        const docs_obj = b.addObject(.{
            .name = "docs",
            .root_source_file = b.path("src/test/cert.zig"),
            .target = target,
            .optimize = .Debug,
        });

        const install_docs = b.addInstallDirectory(.{
            .install_dir = .prefix,
            .install_subdir = "sshkeys",
            .source_dir = docs_obj.getEmittedDocs(),
        });

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
