[![GoDoc](https://godoc.org/github.com/KarpelesLab/spotlib?status.svg)](https://godoc.org/github.com/KarpelesLab/spotlib)

# spotlib

Spot connection library, allows accessing Spot and sending end to end encrypted messages to other participants.

## Usage

```go
c, err := spotlib.New()
if err != nil {
    return err
}
go func() {
    for ev := range c.Events.On("status") {
        if emmiter.Arg[int](ev, 0) == 1 {
            // we are online!
        }
    }
}()
c.SetHandler("endpoint", func(msg *spotproto.Message) ([]byte, error) {
    // handle message
    ...
})
```
