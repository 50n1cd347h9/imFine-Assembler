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

const keywds = instructions ++ registers;

const KeywdId = struct {};

fn isDigit(ch: u8) bool {
    const code = @as(i8, @intCast(ch));
    return 0 <= code - '0' and code - '0' < 10;
}

fn isHex(ch: u8) bool {
    const code = @as(i8, @intCast(ch));
    return (0 <= code - 'a' and code - 'a' < 6) or isDigit(ch);
}

fn isLetter(ch: u8) bool {
    const code = @as(i8, @intCast(ch));
    return (0 <= code - 'a' and code - 'a' < 26) or (0 <= code - 'A' and code - 'A' < 26);
}

fn nextChar(reader: anytype) u8 {
    return reader.readByte() catch 0;
}

const TokenKind = enum {
    label,
    labelDef,
    decLiteral,
    hexLiteral,
    ip,
    sp,
    fp,
    flag,
    gr0,
    gr1,
    push,
    pop,
    add,
    sub,
    mul,
    div,
    and_,
    or_,
    xor,
    shl,
    ld,
    cmp,
    jmp,
    jg,
    jz,
    jl,
    call,
    ret,
    nop,
};

const Token = struct {
    kind: TokenKind,
    val: union(enum) {
        num: u32,
        _buf: [MAX_IDENT_LEN]u8,
    },
    i: u8,

    const Self = @This();

    pub fn ident(self: Self) []const u8 {
        return switch (self.val) {
            ._buf => self.val._buf[0..@intCast(self.i)],
            else => @panic("baka"),
        };
    }
};

const CharKind = enum {
    digit,
    letter,
    other,

    pub fn get(ch: u8) CharKind {
        return switch (ch) {
            'a'...'z' => CharKind.letter,
            '0'...'9' => CharKind.digit,
            else => CharKind.other,
        };
    }
};

fn charClass(ch: u8) CharKind {
    switch (ch) {
        'a'...'z' => {},
        '0'...'9' => {},
        ':' => {},
        else => {},
    }
}

fn streql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const MAX_IDENT_LEN = 0x20;
// TODO: limit skipping whitespaces by setting max spaces
fn nextToken(reader: anytype) Token {
    var ch = nextChar(reader);
    var kind: TokenKind = undefined;
    var num: u32 = 0;
    var buf: [MAX_IDENT_LEN]u8 = [_]u8{0} ** MAX_IDENT_LEN;
    var i: usize = 0;

    // skip whitespace or indent
    while (ch == ' ' or ch == '\t')
        ch = nextChar(reader);

    switch (CharKind.get(ch)) {
        .digit => {
            kind = .decLiteral;
            if (ch == '0') {
                i += 1;
                ch = nextChar(reader);

                if (ch == 'x') {
                    i += 1;
                    ch = nextChar(reader);
                    kind = .hexLiteral;
                    while (isHex(ch)) {
                        num = num * 16 + (ch - '0');
                        i += 1;
                        ch = nextChar(reader);
                    }
                }
            } else {
                while (isDigit(ch)) {
                    num = num * 10 + (ch - '0');
                    i += 1;
                    ch = nextChar(reader);
                }
            }
        },
        .letter => {
            buf[i] = ch;
            i += 1;
            ch = nextChar(reader);

            while ((isLetter(ch) or isDigit(ch)) and i < MAX_IDENT_LEN) {
                buf[i] = ch;
                i += 1;
                ch = nextChar(reader);
            }

            for (0..keywds.len) |k| {
                if (streql(keywds[k], buf[0..i])) {
                    kind = std.meta.stringToEnum(TokenKind, buf[0..i]) orelse @panic("hoge");
                    break;
                }
            } else if (ch == ':') {
                kind = .labelDef;
            } else {
                kind = .label;
            }
        },
        else => {
            @panic("baka");
        },
    }

    return .{
        .kind = kind,
        .val = switch (kind) {
            .decLiteral, .hexLiteral => .{ .num = num },
            else => .{ ._buf = buf },
        },
        .i = @intCast(i),
    };
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
    _ = nextChar(src_reader);

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

test "letter" {
    for ('A'..'Z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ('a'..'z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));

    const failcase = [_]u8{ ':', '.', '`', '_' };
    for (failcase) |letter|
        try std.testing.expect(!isLetter(@intCast(letter)));
}

test "number literal" {
    const fbs = std.io.fixedBufferStream;
    const Tuple = std.meta.Tuple;

    const pass_cases = [_]Tuple(&.{ []const u8, TokenKind, u32 }){
        .{ "0x10 ", .hexLiteral, 0x10 },
        .{ "0x10", .hexLiteral, 0x10 },
        .{ "0", .decLiteral, 0 },
        .{ "10", .decLiteral, 10 },
        .{ "20000", .decLiteral, 20000 },
    };
    for (pass_cases) |case| {
        var stream = fbs(case[0]);
        const reader = stream.reader();
        const token = nextToken(reader);
        try std.testing.expect(token.kind == case[1] and token.val.num == case[2]);
    }
}

test "identifier" {
    const fbs = std.io.fixedBufferStream;
    const Tuple = std.meta.Tuple;

    const pass_cases = [_]Tuple(&.{ []const u8, TokenKind }){
        .{ "hoge", .label },
        //.{ "hoge:", .labelDef },
    };
    for (pass_cases) |case| {
        var stream = fbs(case[0]);
        const reader = stream.reader();
        const token = nextToken(reader);
        //std.debug.print("{d}\n", .{token.i});
        //std.debug.print("{s}\n", .{token.val._buf});
        //std.debug.print("{s}\n", .{token.ident()});
        try std.testing.expect(token.kind == case[1]);
        try std.testing.expectEqualStrings(case[0], token.ident());
    }
    const label_cases = [_]Tuple(&.{ []const u8, TokenKind }){
        .{ "hoge:", .labelDef },
    };
    for (label_cases) |case| {
        var stream = fbs(case[0]);
        const reader = stream.reader();
        const token = nextToken(reader);
        try std.testing.expect(token.kind == case[1]);
        try std.testing.expectEqualStrings(case[0][0 .. case[0].len - 1], token.ident());
    }
}
