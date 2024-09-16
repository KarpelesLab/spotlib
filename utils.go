package spotlib

import (
	"context"
	"encoding/binary"
	"io"
	"time"
)

func writeVarString(w io.Writer, s []byte) error {
	_, err := w.Write(binary.AppendUvarint(nil, uint64(len(s))))
	if err != nil {
		return err
	}
	_, err = w.Write(s)
	return err
}

// WithTimeout makes it easy to call a method that requires a context with a specified timeout
// without having to worry about calling the cancel() method. Go typically suggests using defer,
// however if processing after a given method is called continues, there is a risk the cancel
// method will be called much later.
//
// This method on the other hand performs the defer of cancel, which means that cancel will be
// called properly even in case of a panic.
//
// Usage:
//
//	spotlib.WithTimeout(nil, 30*time.Second, func(ctx context.Context) {
//	   res, err = c.methodWithCtx(ctx)
//	}
//
// if err := nil { ...
func WithTimeout(ctx context.Context, timeout time.Duration, cb func(context.Context)) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cb(ctx)
}
