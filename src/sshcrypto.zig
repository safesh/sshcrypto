//! SSH Keys and Certificates parsing and manipulation utilities.

pub const cert = @import("cert.zig");
pub const key = @import("key.zig");

const std = @import("std");

const Allocator = std.mem.Allocator;

const Base64Decoder = std.base64.Base64Decoder;
const Base64Encoder = std.base64.Base64Encoder;

// TODO: Map errors
pub const Error = error{
    InvalidFileFormat,
} || std.base64.Error || Allocator.Error;

// TODO: AutoDecoder

/// Decode T from PEM to DER.
///
/// TODO: Memory is owned by Der, with refrences to the original data which
/// **SHOULD** outlive Der.
pub fn Decoder(comptime T: type) type {
    if (@typeInfo(T) != .Struct)
        @compileError("Expected struct");

    return struct {
        allocator: Allocator,
        decoder: Base64Decoder,

        const Self = @This();

        /// Unmanaged data with references to data that *SHOULD* outlive it.
        fn Unmanaged(comptime U: type) type {
            return struct {
                data: U,
            };
        }

        /// Managed data with owned memory.
        fn Managed(comptime U: type) type {
            return struct {
                allocator: Allocator,
                data: U,

                pub fn deinit(self: *const @This()) void {
                    self.allocator.free(self.data.der);
                }
            };
        }

        /// Decode T from PEM to DER. This is done in-place, without allocating
        /// memory, changing the reference data. Referenced data must outlive
        /// this.
        pub fn decode_in_place(decoder: Base64Decoder, src: []u8) !Unmanaged(T) {
            var pem: Self.Unmanaged(T) = .{
                .data = try Self.parse_fields(src),
            };

            const len = try decoder.calcSizeForSlice(pem.data.der);

            try decoder.decode(pem.data.der[0..len], pem.data.der);

            pem.data.der.len = len;

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

        pub fn decode(self: *const Self, src: []const u8) !Managed(T) {
            var pem: Self.Managed(T) = .{
                .allocator = self.allocator,
                .data = try Self.parse_fields(src),
            };

            const len = try self.decoder.calcSizeForSlice(pem.data.der);

            const der = try self.allocator.alloc(u8, len);
            errdefer self.allocator.free(der);

            try self.decoder.decode(der, pem.data.der);

            pem.data.der = der;

            return pem;
        }
    };
}
