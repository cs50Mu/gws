package gws

import (
	"testing"
)

func TestUtf8ToRune(t *testing.T) {
	// t.Logf("%v\n", hexPrint([]byte{
	// 	0xf4, 0x90, 0x80, 0x80,
	// }))
	bs := []byte{
		0x41,
		0xc2, 0x81,
		0xe4, 0xb8, 0xad,
		0xe5, 0x9b, 0xbd,
		0xe4, 0xba, 0xba,
		0xf0, 0x9f, 0x98, 0x84,
		0xf0, 0x9f, 0x98, 0xa2,
		0x80,
	}
	for len(bs) > 0 {
		c, size, err := utf8ToRune(bs)
		if err != nil {
			t.Fatalf("expected no err, got err: %v", err)
		}
		t.Logf("%v decoded to %c\n", hexPrint(bs[:size]), c)
		bs = bs[size:]
	}
}
