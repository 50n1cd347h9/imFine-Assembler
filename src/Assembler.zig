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
const COMMENT_START = '#';

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

/// remove indent
/// or brank line
fn preProcess(buf: []u8) !usize {
    const allocator = std.heap.page_allocator;
    const tmp = try allocator.alloc(u8, buf.len);
    defer allocator.free(tmp);

    var i: usize = 0;
    var newline: bool = false;
    var comment: bool = false;
    clean: for (buf) |char| {
        if (comment) {
            if (char == LINE_DELIMITER) {
                comment = false;
            } else {
                continue :clean;
            }
        }

        if (newline) {
            if (char == LINE_DELIMITER) {
                continue :clean;
            }
        }

        switch (char) {
            INDENT => continue :clean,
            LINE_DELIMITER => newline = true,
            COMMENT_START => {
                comment = true;
                continue :clean;
            },
            else => newline = false,
        }

        tmp[i] = char;
        i += 1;
    }
    i -= 1;

    @memset(tmp[i..tmp.len], '\x00');
    @memset(buf, '\x00');
    mem.copyForwards(u8, buf, tmp);

    return i;
}

/// check if syntax is ok
fn validate(buf: []u8) !void {
    const allocator = std.heap.page_allocator;
    const tmp = try allocator.alloc(u8, buf.len);
    defer allocator.free(tmp);

    var buf_idx: usize = 0;
    while (nextLine(buf, &buf_idx)) |line| {
        try validateToken(line);
    }
}

const ValidateState = struct {};

fn isRegister(buf: []const u8) bool {
    for (registers) |register|
        if (eql(u8, buf, register))
            return true;
    return false;
}

fn isOpcode(buf: []const u8) bool {
    for (instructions) |instruction|
        if (eql(u8, buf, instruction))
            return true;
    return false;
}

fn isImm(buf: []const u8) bool {
    var res: ?u128 = 0;
    for ([2]u8{ 10, 16 }) |base| {
        if (buf.len > 2 and
            buf[0] == '0' and
            buf[1] == 'x')
        {
            res = std.fmt.parseInt(u128, buf[2..buf.len], base) catch null;
        } else res = std.fmt.parseInt(u128, buf, base) catch null;
        if (base == 16) {
            if (res == null) {
                return false;
            } else return true;
        }
    }
    return false;
}

fn isRef(buf: []const u8) bool {
    if (buf[0] == SQUARE_BRACKET_OPEN)
        return true;
    return false;
}

fn isLabel(buf: []const u8) bool {
    if (buf[buf.len - 1] == COLON)
        return true;
    return false;
}
fn validateToken(line: []u8) !void {
    var label: bool = false;
    var second_oprand_expected: bool = false;

    var line_idx: usize = 0;
    while (readToken(line, &line_idx)) |token| {
        var new_token: []u8 = token;

        if (label) {
            if (readToken(line, &line_idx)) |invalid_token| {
                debugPrint("invalid token -> %s\n", .{invalid_token});
                return;
            }
        }

        if (second_oprand_expected) {
            if (!readToken(line, &line_idx)) {
                debugPrint("token expected -> %s _\n", .{token});
                return;
            }
            second_oprand_expected = false;
        }

        // if token is label
        if (endWithColon(token)) {
            label = true;
            continue;
        }

        if (endWithComma(token)) {
            second_oprand_expected = true;
            new_token = removeComma(token);
        }

        // for ()
    }
}

inline fn removeComma(token: []u8) []u8 {
    return token[0 .. token.len - 2];
}

inline fn endWithColon(token: []u8) bool {
    return token[token.len - 1] == COLON;
}

inline fn endWithComma(token: []u8) bool {
    return token[token.len - 1] == COMMA;
}

fn readToken(line: []u8, idx: *usize) ?[]u8 {
    const start = idx.*;
    const end = for (line) |char| {
        switch (char) {
            SPACE => {
                defer idx.* += 1;
                break idx.*;
            },
            COMMA => {
                idx.* += 1;
                break idx.*;
            },
            COLON => {
                idx.* += 1;
                break idx.*;
            },
            else => {},
        }
        idx.* += 1;
    };
    const token = line[start..end];

    return if (token.len == 0) null else token;
}

fn nextLine(buf: anytype, idx: *usize) ?[]u8 {
    const start = idx.*;
    const end = for (buf[start..buf.len]) |char| {
        if (char == LINE_DELIMITER)
            break idx.*;
        idx.* += 1;
    } else buf.len;
    const line = buf[start..end];

    return if (line.len == 0) null else line;
}

const instructions = [_][]const u8{
    "push",
    "pop",
    "add",
    "sub",
    "mul",
    "div",
    "and",
    "or",
    "xor",
    "shl",
    "ld",
    "ld",
    "cmp",
    "jmp",
    "jg",
    "jz",
    "jl",
    "call",
    "ret",
    "nop",
};

const registers = [_][]const u8{
    "ip",
    "sp",
    "fp",
    "flag",
    "gr0",
    "gr1",
};

fn isDigit(ch: u8) bool {
    const code = @as(i8, @intCast(ch));
    return code - '0' < 10 and code - '0' >= 0;
}

fn isHex(ch: u8) bool {
    const code = @as(i8, @intCast(ch));
    return (code - 'a' < 6 and code - 'a' >= 0) or isDigit(ch);
}

var index: usize = 0;
fn nextChar(buf: []const u8) u8 {
    defer index += 1;
    return buf[index];
}

fn assemble(self: *ImFineAssembler) !void {
    const src_file = try fs.cwd().openFile(self.src_name, .{ .mode = .read_only });

    self.src_file_buf = try zig.readSourceFileToEndAlloc(self.allocator, src_file, null);
    defer self.allocator.free(self.src_file_buf);

    src_file.close();

    const length = try preProcess(self.src_file_buf);
    _ = length;

    debugPrint("{s}", .{self.src_file_buf});

    // const dst_file = try fs.cwd().createFile(self.dst_name, .{});
    // defer dst_file.close();

    // const output_writer = dst_file.writer();

    // self.tokens = ArrayList(?[]u8).init(self.allocator);
    // defer self.tokens.deinit();

    // self.codes = ArrayList(Code).init(self.allocator);
    // defer self.codes.deinit();

    // self.label_addr = ArrayList(Label2addr).init(self.allocator);
    // defer self.label_addr.deinit();

    // self.out_buf = ArrayList(u8).init(self.allocator);
    // defer self.out_buf.deinit();

    // var tokenizer = Tokenizer.init(self);
    // try tokenizer.tokenize();

    // var parser = Parser.init(self);
    // try parser.parse();

    // var encoder = Encoder.init(self);
    // try encoder.encode();

    // try output_writer.writeAll(self.out_buf.items);
}

pub fn entry(self: *ImFineAssembler) void {
    self.assemble() catch |err| {
        debugPrint("{!}\n", .{err});
        fs.cwd().deleteFile(
            self.dst_name,
        ) catch return;
    };
}

test "digit" {
    const digits = [_]u8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

    for (digits) |digit|
        try std.testing.expect(isDigit(digit));

    try std.testing.expect(!isDigit(':'));
    try std.testing.expect(!isDigit('/'));
}

test "hex" {
    const hexes = [_]u8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    for (hexes) |hex|
        try std.testing.expect(isHex(hex));

    try std.testing.expect(!isHex(':'));
    try std.testing.expect(!isHex('/'));
    try std.testing.expect(!isHex('`'));
    try std.testing.expect(!isHex('g'));
}
