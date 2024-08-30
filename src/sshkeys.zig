//! SSH Keys and Certificates parsing and manipulation utilities.

pub const cert = @import("cert.zig");
pub const key = @import("key.zig");

const std = @import("std");

const Allocator = std.mem.Allocator;
const Base64Decoder = std.base64.Base64Decoder;

pub const Error = error{
    InvalidFileFormat,
} || std.base64.Error || Allocator.Error;

// TODO: AutoDecoder

/// Decode a certificate in PEM format to DER format.
///
/// TODO: Memory is owned by Der, with refrences to the original data which **SHOULD** outlive Der.
pub fn Decoder(comptime T: type) type {
    if (@typeInfo(T) != .Struct)
        @compileError("Expected struct");

    return struct {
        allocator: Allocator,
        decoder: Base64Decoder,

        const Self = @This();

        pub fn decode_in_place(decoder: Base64Decoder, src: []u8) !T {
            var pem = try Self.parse_fields(src);

            const len = try decoder.calcSizeForSlice(pem.der);

            try decoder.decode(pem.der[0..len], pem.der);

            pem.der.len = len;

            return pem;
        }

        pub fn init(allocator: Allocator, decoder: Base64Decoder) Self {
            return .{
                .allocator = allocator,
                .decoder = decoder,
            };
        }

        fn parse_fields(src: []const u8) !T {
            var it = std.mem.tokenizeAny(u8, src, " ");

            var ret: T = undefined;

            inline for (comptime std.meta.fields(T)) |field| {
                const val = it.next() orelse
                    return error.InvalidFileFormat;

                @field(ret, field.name) = switch (field.type) {
                    []u8 => @constCast(val),
                    []const u8 => val,
                    else => @panic("Unkown type"),
                };
            }

            return ret;
        }

        pub fn decode(self: *const Self, src: []const u8) !T {
            var pem = try Self.parse_fields(src);

            const len = try self.decoder.calcSizeForSlice(pem.der);

            const der = try self.allocator.alloc(u8, len);
            errdefer self.allocator.free(der);

            try self.decoder.decode(der, pem.der);

            pem.der = der;

            return pem;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.deinit();
        }
    };
}
