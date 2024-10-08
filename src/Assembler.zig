const std = @import("std");
const Encoder = @import("Encoder.zig");
const Tokenizer = @import("Tokenizer.zig");
const Parser = @import("Parser.zig");

const io = std.io;
const fs = std.fs;
const debugPrint = std.debug.print;
const pow = std.math.pow;
const ArrayList = std.ArrayList;
const mem = std.mem;
const eql = mem.eql;
const copyForwards = mem.copyForwards;
const builtin = std.builtin;
const zig = std.zig;
pub const ByteWidth: type = u32;
const SignedByteWidth: type = @Type(.{ .int = .{
    .bits = @typeInfo(ByteWidth).int.bits,
    .signedness = builtin.Signedness.signed,
} });
const ImFineAssembler = @This();

allocator: mem.Allocator,
tokens: ArrayList(?[]u8),
codes: ArrayList(Code),
label_addr: ArrayList(Label2addr),
src_name: []u8,
dst_name: []u8,
line_buffer: [0x100]u8,
src_file_buf: [:0]u8,
out_buf: ArrayList(u8),

const COMMA: u8 = ',';
const SEMICOLON: u8 = ';';
const SPACE: u8 = ' ';
const SQUARE_BRACKET_OPEN = '[';
const SQUARE_BRACKET_CLOSE = ']';
const INDENT = '\t';
const COLON: u8 = ':';
const EOL = '\x00';
const LABEL: u8 = 0b11 << 6;
const TOKEN_DELIMITER = '\x00';
const LINE_DELIMITER = '\n';

var DEBUG = false;

const filename_len = 0x200;
var file_name_buf = [_]u8{0} ** (filename_len);

pub const SyntaxError = error{
    CommaNeeded,
    OpenSquareBracketNeeded,
    CloseSquareBracketNeeded,
    LabelNotFound,
    UnknownToken,
};

const ArgError = error{
    FileNotFound,
    TooFewArgs,
};

pub const Code = struct {
    opcode: u8,
    ext: u2,
    len: u3,
    first_oprand: u8,
    padding: u2,
    second_oprand: u128,
};

pub const Label2addr = struct {
    label_str: []u8,
    label_idx: ByteWidth,
    addr_abs: ByteWidth,
};

pub const LabelSlot = struct {
    place: ByteWidth, // blank place that should be resolved
    label_idx: ByteWidth,
};

pub fn init(allocator: mem.Allocator) ImFineAssembler {
    @memset(&file_name_buf, 0);

    return ImFineAssembler{
        .allocator = allocator,
        .src_name = undefined,
        .dst_name = undefined,
        .line_buffer = undefined,
        .label_addr = undefined,
        .tokens = undefined,
        .codes = undefined,
        .src_file_buf = undefined,
        .out_buf = undefined,
    };
}

// *const [][:0]u8 = pointer to an array of zero terminated const u8 values
pub fn parseArgs(self: *ImFineAssembler, args_p: *const [][:0]u8) !void {
    if (args_p.len < 2)
        return ArgError.TooFewArgs;

    for (args_p.*, 0..) |arg, i| {
        if (i == 0) continue;
        if (eql(u8, arg, "--debug")) {
            DEBUG = true;
            continue;
        }
        // arg is file name
        copyForwards(u8, &file_name_buf, arg);
        self.src_name = arg;
    }
    self.assignOutputName();
}

fn nameEndWithAsm(file_name: []u8) bool {
    const length = file_name.len;
    return eql(
        u8,
        file_name[length - 4 .. length],
        ".asm",
    );
}

fn assignOutputName(self: *ImFineAssembler) void {
    const extension = ".bin";
    const src_name_len = self.src_name.len;

    if (nameEndWithAsm(self.src_name)) {
        copyForwards(
            u8,
            file_name_buf[src_name_len - 4 .. src_name_len],
            extension,
        );
        self.dst_name = file_name_buf[0..src_name_len];
    } else {
        copyForwards(
            u8,
            file_name_buf[src_name_len - 1 .. src_name_len + 3],
            extension,
        );
        self.dst_name = file_name_buf[0 .. src_name_len + extension.len];
    }
}

pub fn getLen(num: u128) u3 {
    return switch (num) {
        0 => 0b000,
        1...(pow(u16, 2, 8) - 1) => 0b001,
        pow(u16, 2, 8)...(pow(u32, 2, 16) - 1) => 0b010,
        pow(u32, 2, 16)...(pow(u64, 2, 32) - 1) => 0b011,
        pow(u64, 2, 32)...(pow(u128, 2, 64) - 1) => 0b100,
        pow(u128, 2, 64)...(pow(u129, 2, 128) - 1) => 0b100,
    };
}

fn assemble(self: *ImFineAssembler) !void {
    const src_file = try fs.cwd().openFile(self.src_name, .{ .mode = .read_only });
    self.src_file_buf = try zig.readSourceFileToEndAlloc(self.allocator, src_file, null);
    defer self.allocator.free(self.src_file_buf);
    src_file.close();

    const dst_file = try fs.cwd().createFile(self.dst_name, .{});
    defer dst_file.close();
    const output_writer = dst_file.writer();

    self.tokens = ArrayList(?[]u8).init(self.allocator);
    defer self.tokens.deinit();
    self.codes = ArrayList(Code).init(self.allocator);
    defer self.codes.deinit();
    self.label_addr = ArrayList(Label2addr).init(self.allocator);
    defer self.label_addr.deinit();
    self.out_buf = ArrayList(u8).init(self.allocator);
    defer self.out_buf.deinit();

    var tokenizer = Tokenizer.init(self);
    try tokenizer.tokenize();

    var parser = Parser.init(self);
    try parser.parse();

    var encoder = Encoder.init(self);
    try encoder.encode();

    try output_writer.writeAll(self.out_buf.items);
}

pub fn entry(self: *ImFineAssembler) void {
    self.assemble() catch |err| {
        debugPrint("{!}\n", .{err});
        fs.cwd().deleteFile(
            self.dst_name,
        ) catch return;
    };
}
