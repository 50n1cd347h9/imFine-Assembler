pub var tokens: Tokens = Tokens{};
var _ch: u8 = ' ';
var buffer: [0x1000]u8 = undefined;
var fba = std.heap.FixedBufferAllocator.init(&buffer);
const a = fba.allocator();

pub fn init() void {
    _ch = ' ';
    tokens.clearAndFree(a);
    //tokens.setCapacity(MAX_TOKENS);
}

pub fn deinit() void {
    _ch = ' ';
    tokens.clearAndFree(a);
    //tokens.deinit(a);
}

pub fn testTokenizerInit() void {
    _ch = ' ';
}

pub const TokenKind = enum {
    label,
    labelDef,
    numberLiteral,
    //decLiteral,
    //hexLiteral,
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
    mov,
    nop,
    newline,
    eof,
    sqbrac_l,
    sqbrac_r,

    pub fn get(buf: []const u8) ?TokenKind {
        return std.meta.stringToEnum(TokenKind, buf) orelse blk: {
            var tmp = [_]u8{'_'} ** MAX_IDENT_LEN;
            std.mem.copyForwards(u8, &tmp, buf);
            break :blk std.meta.stringToEnum(TokenKind, tmp[0 .. buf.len + 1]);
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
    sqbrac_l,
    sqbrac_r,

    // TODO: define comment(#)
    pub fn get(ch: u8) CharKind {
        return switch (ch) {
            'a'...'z', 'A'...'Z' => .letter,
            '0'...'9' => .digit,
            '[' => .sqbrac_l,
            ']' => .sqbrac_r,
            '\n' => .newline,
            ',' => .comma,
            ':' => .colon,
            EOF => .eof,
            else => .other,
        };
    }
};

const hash_fn = std.hash.RapidHash.hash;
const HashType: type = @typeInfo(@TypeOf(hash_fn)).@"fn".return_type.?;

pub const Token = struct {
    kind: TokenKind,
    id: ?HashType, // nullable

    pub fn hash(input: []const u8) HashType {
        const hash_key = 0xdeadbeef;
        return hash_fn(hash_key, input);
    }
};

pub const Label = struct {
    hash: HashType,
    idx: usize,
};

const Tokens: type = std.MultiArrayList(Token);

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

fn streql(one: []const u8, two: []const u8) bool {
    return std.mem.eql(u8, one, two);
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
            kind = .numberLiteral;
            //kind = .decLiteral;
            if (ch == '0') {
                i += 1;
                ch = nextChar(reader);

                if (ch == 'x') {
                    //kind = .hexLiteral;
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
        .sqbrac_l => {
            kind = .sqbrac_l;
            ch = nextChar(reader);
        },
        .sqbrac_r => {
            kind = .sqbrac_r;
            ch = nextChar(reader);
        },
        .eof => {
            kind = .eof;
        },
        else => {
            dbgprint("|{c}|{x}|\n", .{ ch, ch });
            @panic("character unaccepted");
        },
    }

    const token = Token{
        .kind = kind,
        .id = switch (kind) {
            .numberLiteral => num,
            .label, .labelDef => Token.hash(buf[0..i]),
            else => null,
        },
    };

    tokens.append(a, token) catch @panic("aaaaaa");
    return token;
}

test "digit" {
    for (0..10) |i|
        try std.testing.expect(isDigit(@intCast('0' + i)));
    for ([_]u8{ ':', '/', '`', 'g' }) |ch|
        try std.testing.expect(!isDigit(ch));
}

test "hex" {
    for (0..10) |i|
        try std.testing.expect(isHex(@intCast('0' + i)));
    for (0..6) |i|
        try std.testing.expect(isHex(@intCast('a' + i)));
    for ([_]u8{ ':', '/', '`', 'g' }) |ch|
        try std.testing.expect(!isHex(ch));
}

test "letter" {
    for ('A'..'Z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ('a'..'z' + 1) |letter|
        try std.testing.expect(isLetter(@intCast(letter)));
    for ([_]u8{ ':', '.', '`', '_' }) |letter|
        try std.testing.expect(!isLetter(@intCast(letter)));
}

test "token kind" {
    const pass_cases = [_]TestCase(TokenKind){
        .{ "and", .and_ },
        .{ "or", .or_ },
        .{ "ld", .ld },
        .{ "xor", .xor },
        .{ "call", .call },
        .{ "[", .sqbrac_l },
        .{ "]", .sqbrac_r },
    };

    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const kind = case;
        if (TokenKind.get(input)) |_kind|
            try std.testing.expect(_kind == kind);
    }
}

test "TokenKind accept all keywords" {
    for (keywds) |keywd|
        try std.testing.expect(TokenKind.get(keywd) != null);
}

test "number literal" {
    const Expected = .{ TokenKind, u32 };
    const pass_cases = [_]TestCase(Expected){
        .{ "0x10 ", .{ .numberLiteral, 0x10 } },
        .{ "0x10", .{ .numberLiteral, 0x10 } },
        .{ "0", .{ .numberLiteral, 0 } },
        .{ "10", .{ .numberLiteral, 10 } },
        .{ "20000", .{ .numberLiteral, 20000 } },
    };
    for (pass_cases) |case| {
        defer testTokenizerInit();
        const input, const expected = case;
        const kind, const val = expected;

        var stream = fbs(input);
        const reader = stream.reader();
        const token = nextToken(reader);

        try std.testing.expect(token.kind == kind);
        try std.testing.expect(token.id == val);
    }
}

test "identifier" {
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

        try std.testing.expect(token.kind == kind);
        try std.testing.expect(Token.hash(exptd_str) == token.id);
    }
}

test "trailing identifier" {
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
            try std.testing.expect(token.kind == kind);
            try std.testing.expect(Token.hash(exptd_str) == token.id.?);
        }
    }
}

test "program" {
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
            .numberLiteral => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            .label, .labelDef => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            else => {},
        }
        token = nextToken(reader);
    }
}

test "program2" {
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
            .numberLiteral => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            .label, .labelDef => dbgprint("{d: <9} {}\n", .{ token.id.?, token.kind }),
            else => {},
        }
        token = nextToken(reader);
    }
}

test "and instruction" {
    const program_str =
        \\and gr0, 1 
        \\
    ;
    const Expected = []const TokenKind;
    const pass_cases = [_]TestCase(Expected){
        .{ program_str, &.{ .and_, .gr0, .comma, .numberLiteral, .newline, .eof } },
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
const parser = @import("parser.zig");
const registers = consts.registers;
const instructions = consts.instructions;
const dbgprint = std.debug.print;
const fbs = std.io.fixedBufferStream;
const Tuple = std.meta.Tuple;
const panic = std.debug.panic;
const TestCase = property.TestCase;
const runTest = property.runTest;
const MAX_IDENT_LEN = consts.MAX_IDENT_LEN;
const MAX_TOKEN_BUF = consts.MAX_TOKEN_BUF;
const MAX_TOKENS = consts.MAX_TOKENS;
const EOF = consts.EOF;
const keywds = consts.keywds;
