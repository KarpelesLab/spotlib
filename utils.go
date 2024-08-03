package spotlib

import (
	"encoding/binary"
	"io"
)

func writeVarString(w io.Writer, s []byte) error {
	_, err := w.Write(binary.AppendUvarint(nil, uint64(len(s))))
	if err != nil {
		return err
	}
	_, err = w.Write(s)
	return err
}
