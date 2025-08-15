package fingerprint

import (
	"bytes"

	"github.com/mdp/qrterminal/v3"
)

func QrCode(b []byte) ([]byte, error) {
	var buffer bytes.Buffer
	qrterminal.Generate(string(b), qrterminal.L, &buffer)
	return buffer.Bytes(), nil
}
