pub const ByteWidth: type = u32;
const SignedByteWidth: type = @Type(.{ .int = .{
    .bits = @typeInfo(ByteWidth).int.bits,
    .signedness = builtin.Signedness.signed,
} });
const ImFineAssembler = @This();

src_name: []u8,

const ArgError = error{
    FileNotFound,
    TooFewArgs,
};

pub fn init(allocator: mem.Allocator) ImFineAssembler {
    _ = allocator;

    return ImFineAssembler{
        .src_name = undefined,
    };
}

// *const [][:0]u8 = pointer to an array of zero terminated const u8 values
pub fn parseArgs(self: *ImFineAssembler, args_p: *const [][:0]u8) !void {
    _ = self;
    if (args_p.len < 2)
        return ArgError.TooFewArgs;

    for (args_p.*, 0..) |arg, i| {
        _ = arg;
        if (i == 0) continue;
        //if (eql(u8, arg, "--debug")) {
        //    DEBUG = true;
        //    continue;
        //}
        // arg is file name
        // copyForwards(u8, &file_name_buf, arg);
        //self.src_name = arg;
    }
    //self.assignOutputName();
}

fn nameEndWithAsm(file_name: []u8) bool {
    const length = file_name.len;
    return eql(
        u8,
        file_name[length - 4 .. length],
        ".asm",
    );
}

fn memoryReference() void {}

fn instruction() void {}
// fn label() void {}
fn program() void {
    instruction();
}

fn assemble(self: *ImFineAssembler) !void {
    const src_file = try fs.cwd().openFile(self.src_name, .{ .mode = .read_only });
    defer src_file.close();
    const src_reader = src_file.reader();
    _ = src_reader;
    //_ = nextChar(src_reader);

    program();
}

pub fn entry(self: *ImFineAssembler) void {
    self.assemble() catch |err| {
        debugPrint("{!}\n", .{err});
        //fs.cwd().deleteFile(
        //    self.dst_name,
        //) catch return;
    };
}

const std = @import("std");
const Encoder = @import("Encoder.zig");
const Tokenizer = @import("Tokenizer.zig");
const Parser = @import("Parser.zig");

const mem = std.mem;
const eql = mem.eql;
const io = std.io;
const fs = std.fs;
const debugPrint = std.debug.print;
const pow = std.math.pow;
const ArrayList = std.ArrayList;
const copyForwards = mem.copyForwards;
const builtin = std.builtin;
const zig = std.zig;
