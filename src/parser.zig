//! parser.zig is responsible for parsing assembly
//! and making identifier table

var token: Token = undefined;

const ParseError = error{
    CommaExpected,
    InstructionExpected,
    TokenAfterInstruction,
    NumberLiteralExpected,
    RegisterExpected,
};

fn insPush(reader: anytype) void {
    _ = reader;
}

fn insAnd(reader: anytype) ParseError!void {
    switch (token.kind) {
        .gr0, .gr1, .sp, .fp => {
            token = nextToken(reader);
            readComma(token) catch |e| return e;
            token = nextToken(reader);
            switch (token.kind) {
                .decLiteral, .hexLiteral => {
                    _ = 1;
                },
                else => return error.NumberLiteralExpected,
            }
        },
        else => return error.RegisterExpected,
    }
}

fn readComma(_token: Token) ParseError!void {
    if (_token.kind != .comma)
        return error.CommaExpected;
}

fn labelDef(_: anytype) void {}

fn instruction(reader: anytype) ParseError!void {
    //dbgprint("tok: {s}\n", .{token.ident()});
    switch (token.kind) {
        .push => {
            token = nextToken(reader);
            insPush(reader);
        },
        .pop => {},
        .add => {},
        .sub => {},
        .mul => {},
        .div => {},
        .and_ => {
            token = nextToken(reader);
            insAnd(reader) catch |e| return e;
        },
        .or_ => {},
        .xor => {},
        .shl => {},
        .ld => {},
        .cmp => {},
        .jmp => {},
        .jg => {},
        .jz => {},
        .jl => {},
        .call => {},
        .ret => {},
        .nop => {},
        else => return error.InstructionExpected,
    }
}

fn program(reader: anytype) ParseError!void {
    token = nextToken(reader);

    while (token.kind == .newline)
        token = nextToken(reader);

    while (true) {
        //dbgprint("{}\n", .{token.kind});
        switch (token.kind) {
            .newline => {
                token = nextToken(reader);
            },
            .labelDef => {
                @panic("labelDef");
                //token = nextToken(reader);
                //labelDef(reader);
            },
            .eof => break,
            else => {
                instruction(reader) catch |e| return e;
                token = nextToken(reader);
                switch (token.kind) {
                    .newline, .eof => {
                        token = nextToken(reader);
                    },
                    else => return error.TokenAfterInstruction,
                }
            },
        }
    }
}

test "and instruction" {
    runTest("-- program --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, 1 
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try program(reader);
}

test "comma expected" {
    runTest("-- comma expected --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.CommaExpected, program(reader));
}

test "instruction expected" {
    runTest("-- instruction expected --");

    defer testTokenizerInit();
    const program_str =
        \\gr0 1
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.InstructionExpected, program(reader));
}

test "and instruction fail" {
    runTest("-- and instruction fail --");

    defer testTokenizerInit();
    const program_str =
        \\and gr0, 1  ddd
        \\
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    try expectError(ParseError.TokenAfterInstruction, program(reader));
}

const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const property = @import("property.zig");
const Token = tokenizer.Token;
const testTokenizerInit = tokenizer.testTokenizerInit;
const runTest = property.runTest;
const nextToken = tokenizer.nextToken;
const fbs = std.io.fixedBufferStream;
const dbgprint = std.debug.print;
const panic = std.debug.panic;
const expect = std.testing.expect;
const expectError = std.testing.expectError;
