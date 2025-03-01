const MAX_IDENT_LEN = 0x20;
const MAX_TOKEN_BUF = 0x1000;
var token_buffer: [MAX_TOKEN_BUF]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&token_buffer);
var tok_a = fba.allocator();

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
    u: union(enum) {
        _num: u32,
        _buf: []u8,
    },

    const Self = @This();

    pub fn ident(self: Self) []const u8 {
        return switch (self.u) {
            ._buf => self.u._buf,
            else => @panic("access violation: .u._buf not initialized"),
        };
    }
    pub fn val(self: Self) u32 {
        return switch (self.u) {
            ._num => self.u._num,
            else => @panic("access violation: .u._num not initialized"),
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

fn streql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

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
        .u = switch (kind) {
            .decLiteral, .hexLiteral => .{ ._num = num },
            else => .{ ._buf = tok_a.dupe(u8, buf[0..i]) catch @panic("out of memory: fixed buffer allocator") },
        },
    };
}

test "digit" {
    const digits = [_]u8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    for (digits) |digit|
        try std.testing.expect(isDigit(digit));

    const fail_case = [_]u8{ ':', '/', '`', 'g' };
    for (fail_case) |ch|
        try std.testing.expect(!isDigit(ch));
}

test "hex" {
    const hexes = [_]u8{ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    for (hexes) |hex|
        try std.testing.expect(isHex(hex));

    const fail_case = [_]u8{ ':', '/', '`', 'g' };
    for (fail_case) |ch|
        try std.testing.expect(!isHex(ch));
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
        try std.testing.expect(token.kind == case[1] and token.val() == case[2]);
    }
}

test "identifier" {
    const pass_cases = [_]Tuple(&.{ []const u8, TokenKind }){
        .{ "hoge", .label },
        //.{ "hoge:", .labelDef },
    };
    for (pass_cases) |case| {
        var stream = fbs(case[0]);
        const reader = stream.reader();
        const token = nextToken(reader);
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

test "trailing identifier" {
    const TestCase: type = Tuple(&[_]type{
        []const u8,
        []const []const u8,
        []const TokenKind,
    });

    // this fails: const pass_cases: []TestCase = .{ hogehoge };
    const pass_cases = [_]TestCase{
        .{ "trailing identifier ", &.{ "trailing", "identifier" }, &.{ .label, .label } },
        .{ "trailing: identifier ", &.{ "trailing", "identifier" }, &.{ .labelDef, .label } },
    };

    for (pass_cases) |case| {
        const test_string, const exptd_strs, const kinds = case;
        var stream = fbs(test_string);
        const reader = stream.reader();

        for (kinds, exptd_strs) |kind, exptd_str| {
            const token = nextToken(reader);
            //std.debug.print("/{s}/\n", .{token.ident()});
            //std.debug.print("/{s}/{d}\n", .{ token.val._buf, token.i });
            try std.testing.expect(token.kind == kind);
            try std.testing.expectEqualStrings(exptd_str, token.ident());
        }
    }
}

const std = @import("std");
const ArrayList = std.ArrayList;
const debugPrint = std.debug.print;
const fbs = std.io.fixedBufferStream;
const Tuple = std.meta.Tuple;
