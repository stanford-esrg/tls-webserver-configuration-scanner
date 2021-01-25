package defaults

import (
	"bytes"
)

func Strconcat(x1 string, x2 string) string {
	var buf bytes.Buffer
	buf.WriteString(x1)
	buf.WriteString(x2)
	return buf.String()
}
