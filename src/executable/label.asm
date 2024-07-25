ld gr0, 4
jmp aiueo

hogehoge:
	shl gr0, 4
	jmp huga

aiueo:
	jmp hogehoge

huga:
	sub gr0, 2
	jmp hoge

hoge:
	add gr0, 1
