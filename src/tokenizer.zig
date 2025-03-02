var token_buffer: [MAX_TOKEN_BUF]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&token_buffer);
var tok_a = fba.allocator();

const TokenKind = enum {
    label,
    labelDef,
    decLiteral,
    hexLiteral,
    comma,
    ip,
    flag,
    sp,
    fp,
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
    newline,
    eof,

    const Self = @This();
    pub fn get(buf: []const u8) ?Self {
        return std.meta.stringToEnum(Self, buf) orelse blk: {
            var tmp = [_]u8{'_'} ** MAX_IDENT_LEN;
            std.mem.copyForwards(u8, &tmp, buf);
            break :blk std.meta.stringToEnum(Self, tmp[0 .. buf.len + 1]);
        };
    }
};

const CharKind = enum {
    digit,
    letter,
    comma,
    eof,
    newline,
    colon,
    other,

    const Self = @This();
    pub fn get(ch: u8) Self {
        return switch (ch) {
            'a'...'z', 'A'...'Z' => .letter,
            '0'...'9' => .digit,
            '\n' => .newline,
            ',' => .comma,
            ':' => .colon,
            EOF => .eof,
            else => .other,
        };
    }
};

pub const Token = struct {
    kind: TokenKind,
    u: union(enum) {
        _val: u32,
        _ident: []u8,
    },

    const Self = @This();

    //pub fn set(tmp: anytype) void {
    //    _ = tmp;
    //}
    pub fn ident(self: Self) []const u8 {
        return switch (self.u) {
            ._ident => self.u._ident,
            else => @panic("access violation: .u._buf not initialized"),
        };
    }
    pub fn val(self: Self) u32 {
        return switch (self.u) {
            ._val => self.u._val,
            else => @panic("access violation: .u._num not initialized"),
        };
    }
};

fn isRegister(token: []const u8) bool {
    for (registers) |register|
        return streql(token, register);
    return false;
}

fn isInstruction(token: []const u8) bool {
    for (instructions) |instruction|
        return streql(token, instruction);
    return false;
}

fn isKeyword(token: []const u8) bool {
    return isRegister(token) or isInstruction(token);
}

fn streql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn isDigit(ch: u8) bool {
    const code = @as(i8, @bitCast(ch));
    return 0 <= code - '0' and code - '0' < 10;
}

fn isHex(ch: u8) bool {
    const code = @as(i8, @bitCast(ch));
    return (0 <= code - 'a' and code - 'a' < 6) or isDigit(ch);
}

fn isLetter(ch: u8) bool {
    const code = @as(i8, @bitCast(ch));
    return (0 <= code - 'a' and code - 'a' < 26) or (0 <= code - 'A' and code - 'A' < 26);
}

fn nextChar(reader: anytype) u8 {
    return reader.readByte() catch EOF;
}

pub fn testTokenizerInit() void {
    _ch = ' ';
}

var _ch: u8 = ' ';
pub fn nextToken(reader: anytype) Token {
    var kind: TokenKind = undefined;
    var num: u32 = 0;
    var buf: [MAX_IDENT_LEN]u8 = [_]u8{0} ** MAX_IDENT_LEN;
    var i: usize = 0;
    var ch = _ch;
    defer _ch = ch;

    while (ch == ' ' or ch == '\t')
        ch = nextChar(reader);

    switch (CharKind.get(ch)) {
        .digit => {
            kind = .decLiteral;
            if (ch == '0') {
                i += 1;
                ch = nextChar(reader);

                if (ch == 'x') {
                    kind = .hexLiteral;
                    i += 1;
                    ch = nextChar(reader);
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

            if (TokenKind.get(buf[0..i])) |_kind| {
                kind = _kind;
            } else if (ch == ':') {
                kind = .labelDef;
                ch = nextChar(reader);
            } else {
                kind = .label;
            }
        },
        .newline => {
            kind = .newline;
            ch = nextChar(reader);
        },
        .comma => {
            kind = .comma;
            ch = nextChar(reader);
        },
        .eof => {
            kind = .eof;
        },
        else => {
            debugPrint("|{c}|{x}|\n", .{ ch, ch });
            @panic("character unaccepted");
        },
    }

    return .{
        .kind = kind,
        .u = switch (kind) {
            .decLiteral, .hexLiteral => .{ ._val = num },
            else => .{ ._ident = tok_a.dupe(u8, buf[0..i]) catch @panic("out of memory: fixed buffer allocator") },
        },
    };
}

test "digit" {
    runTest("-- digit --");

    for (0..10) |i|
        try std.testing.expect(isDigit(@intCast('0' + i)));
    for ([_]u8{ ':', '/', '`', 'g' }) |ch|
        try std.testing.expect(!isDigit(ch));
}

test "hex" {
    runTest("-- hex --");

    for (0..10) |i|
        try std.testing.expect(isHex(@intCast('0' + i)));
    for (0..6) |i|
        try std.testing.expect(isHex(@intCast('a' + i)));
    for ([_]u8{ ':', '/', '`', 'g' }) |ch|
        try std.testing.expect(!isHex(ch));
}

test "letter" {
    runTest("-- letter --");

    for ('A'..'Z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ('a'..'z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ([_]u8{ ':', '.', '`', '_' }) |letter|
        try std.testing.expect(!isLetter(@intCast(letter)));
}

test "token kind" {
    runTest("-- token kind --");

    const pass_cases = [_]TestCase(TokenKind){
        .{ "and", .and_ },
        .{ "or", .or_ },
        .{ "ld", .ld },
        .{ "xor", .xor },
        .{ "call", .call },
    };

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const kind = case;
        if (TokenKind.get(input)) |_kind|
            try std.testing.expect(_kind == kind);
    }
}

test "TokenKind accept all keywords" {
    runTest("-- TokenKind accept all keywords --");
    for (keywds) |keywd|
        try std.testing.expect(TokenKind.get(keywd) != null);
}

test "number literal" {
    runTest("-- number literal --");
    const Expected = .{ TokenKind, u32 };
    const pass_cases = [_]TestCase(Expected){
        .{ "0x10 ", .{ .hexLiteral, 0x10 } },
        .{ "0x10", .{ .hexLiteral, 0x10 } },
        .{ "0", .{ .decLiteral, 0 } },
        .{ "10", .{ .decLiteral, 10 } },
        .{ "20000", .{ .decLiteral, 20000 } },
    };
    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const kind, const val = expected;

        var stream = fbs(input);
        const reader = stream.reader();
        const token = nextToken(reader);

        try std.testing.expect(token.kind == kind);
        try std.testing.expect(token.val() == val);
    }
}

test "identifier" {
    runTest("-- identifier --");

    const Expected = .{ []const u8, TokenKind };
    const pass_cases = [_]TestCase(Expected){
        .{ "hoge", .{ "hoge", .label } },
        .{ "hoge:", .{ "hoge", .labelDef } },
    };

    const hoge = u8;
    _ = TestCase(hoge);

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const exptd_str, const kind = expected;
        var stream = fbs(input);
        const reader = stream.reader();
        const token = nextToken(reader);
        defer tok_a.free(token.ident());

        try std.testing.expect(token.kind == kind);
        try std.testing.expectEqualStrings(exptd_str, token.ident());
    }
}

test "trailing identifier" {
    runTest("-- traling identifier --");

    const Expected = .{
        []const []const u8, // tokenized identifiers
        []const TokenKind,
    };
    // this fails: const pass_cases: []TestCase = .{ hogehoge };
    const pass_cases = [_]TestCase(Expected){
        .{ "trailing identifier ", .{ &.{ "trailing", "identifier" }, &.{ .label, .label } } },
        .{ "trailing: identifier ", .{ &.{ "trailing", "identifier" }, &.{ .labelDef, .label } } },
    };

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const strs, const kinds = expected;
        var stream = fbs(input);
        const reader = stream.reader();

        for (kinds, strs) |kind, exptd_str| {
            const token = nextToken(reader);
            const ident = token.ident();
            defer tok_a.free(ident);
            //dbgprint("{s} => {s}\n", .{ exptd_str, ident });
            //dbgprint("{any} => {any}\n", .{ exptd_str, ident });
            try std.testing.expect(token.kind == kind);
            try std.testing.expectEqualStrings(exptd_str, ident);
        }
    }
}

test "program" {
    runTest("-- program --");
    defer testTokenizerInit();
    const program_str =
        \\ld gr0, 4
        \\jmp aiueo
        \\hogehoge:
        \\shl gr0, 4
        \\jmp huga
        \\
        \\
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    var token = nextToken(reader);
    while (token.kind != .eof) {
        switch (token.kind) {
            .decLiteral, .hexLiteral => debugPrint("{d: <9} {}\n", .{ token.val(), token.kind }),
            else => debugPrint("{s: <9} {}\n", .{ token.ident(), token.kind }),
        }
        token = nextToken(reader);
    }
}

test "program2" {
    runTest("-- program2 --");
    defer testTokenizerInit();
    const program_str =
        \\ld gr0, 4
        \\jmp aiueo
        \\hogehoge:
        \\shl gr0, 4
        \\jmp huga
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    var token = nextToken(reader);
    while (token.kind != .eof) {
        switch (token.kind) {
            .decLiteral, .hexLiteral => debugPrint("{d: <9} {}\n", .{ token.val(), token.kind }),
            else => debugPrint("{s: <9} {}\n", .{ token.ident(), token.kind }),
        }
        token = nextToken(reader);
    }
}

test "and instruction" {
    runTest("-- program --");

    const program_str =
        \\and gr0, 1 
        \\
    ;
    const Expected = []const TokenKind;
    const pass_cases = [_]TestCase(Expected){
        .{ program_str, &.{ .and_, .gr0, .comma, .decLiteral, .newline, .eof } },
    };

    var stream = fbs(program_str);
    const reader = stream.reader();
    for (pass_cases) |case| {
        defer testTokenizerInit();
        _, const expected = case;

        for (expected) |kind| {
            const token = nextToken(reader);
            dbgprint("e: {}, a: {}\n", .{ kind, token.kind });
            try std.testing.expect(token.kind == kind);
        }
    }
}

const std = @import("std");
const property = @import("property.zig");
const consts = @import("consts.zig");
const registers = consts.registers;
const instructions = consts.instructions;
const debugPrint = std.debug.print;
const dbgprint = std.debug.print;
const fbs = std.io.fixedBufferStream;
const Tuple = std.meta.Tuple;
const panic = std.debug.panic;
const TestCase = property.TestCase;
const runTest = property.runTest;
const MAX_IDENT_LEN = consts.MAX_IDENT_LEN;
const MAX_TOKEN_BUF = consts.MAX_TOKEN_BUF;
const EOF = consts.EOF;
const keywds = consts.keywds;
