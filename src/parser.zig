//! parser.zig is responsible for parsing assembly
//! and making identifier table

var token: Token = undefined;

fn insPush(reader: anytype) void {
    _ = reader;
}
fn insAnd() void {}

fn labelDef(_: anytype) void {}

fn instruction(reader: anytype) void {
    switch (token.kind) {
        .push => {
            token = nextToken(reader);
            insPush(reader);
        },
        .And => {
            token = nextToken(reader);
            insAnd(reader);
        },
        else => @panic("unknown instruction"),
    }
}

fn program(reader: anytype) void {
    token = nextToken(reader);

    while (token.kind == .newline)
        token = nextToken(reader);

    while (true) {
        switch (token.kind) {
            .newline => {
                token = nextToken(reader);
            },
            .labelDef => {
                token = nextToken(reader);
                labelDef(reader);
            },
            .eof => break,
            else => {
                instruction(reader);
            },
            //else => @panic("unknow token"),
        }
    }
}

test "program" {
    runTest("-- program --");
    const program_str =
        \\ld gr0, 4
        \\jmp aiueo
        \\hogehoge:
        \\shl gr0, 4
        \\jmp huga
    ;
    var stream = fbs(program_str);
    const reader = stream.reader();
    _ = reader;
    //var token = nextToken(reader);
    //while (token.kind != .eof) {
    //    switch (token.kind) {
    //        .decLiteral, .hexLiteral => dbgprint("{d: <9} {}\n", .{ token.val(), token.kind }),
    //        else => dbgprint("{s: <9} {}\n", .{ token.ident(), token.kind }),
    //    }
    //    token = nextToken(reader);
    //}
}
const std = @import("std");
const tokenizer = @import("tokenizer.zig");
const property = @import("property.zig");
const Token = tokenizer.Token;
const runTest = property.runTest;
const nextToken = tokenizer.nextToken;
const fbs = std.io.fixedBufferStream;
const dbgprint = std.debug.print;
