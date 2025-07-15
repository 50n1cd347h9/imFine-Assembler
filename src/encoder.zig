const Self: type = @This();

pub const Code: type = struct {
    opcode: u6,
    ext: u2,
    len: u3,
    reg: u3,
    padding: u2,
    imm_reg: u128,

    pub const Ext = enum(u2) {
        imm,
        reg,
        ref_imm,
        ref_reg,
    };

    pub const Len = enum(u3) {
        bit0,
        bit8,
        bit16,
        bit32,
        bit64,
        bit128,
    };

    pub fn init() Code {
        return Code{
            .opcode = 0,
            .ext = 0,
            .len = 0,
            .reg = 0,
            .padding = 0,
            .imm_reg = 0,
        };
    }

};

initialized: bool,
codes: std.MultiArrayList(Code),

var buffer = [_]u8{0} ** 0x1000;
var fba = std.heap.FixedBufferAllocator.init(&buffer);
const a = fba.allocator();

pub fn init() Self {
    return .{
        .initialized = true,
        .codes = std.MultiArrayList(Code){},
    };
}

pub fn isInitalized(self: Self) bool {
    return self.initialized;
}

pub fn emitCode(self: Self, code: *Code) !void {
    self.codes.append(a, code) catch @panic("error @ emitCode");
}

const std = @import("std");
