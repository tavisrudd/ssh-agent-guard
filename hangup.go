package main

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// watchersRunning counts running watchers (tests check idle connections
// run none).
var watchersRunning atomic.Int32

// watchHangup calls cancel when the client closes its end of conn, and
// returns when ctx ends. agent.ServeAgent reads nothing while a sign
// request waits for confirmation, so without this a request whose client
// has gone (a Ctrl-C'd push) would wait out its turn for the YubiKey and
// its touch timeout, blinking for nobody. Run only while a request is
// confirming: each watcher holds an OS thread in poll.
//
// It polls for POLLHUP only: on a Unix stream socket that is set once the
// peer has closed (both directions shut down), not on a half-close or on
// pending data, which ServeAgent reads in its own time. The poll runs
// inside RawConn.Control, which holds the descriptor open meanwhile; the
// short timeout lets a closing handler finish promptly.
func watchHangup(ctx context.Context, conn net.Conn, cancel context.CancelFunc) {
	watchersRunning.Add(1)
	defer watchersRunning.Add(-1)
	sc, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	for ctx.Err() == nil {
		var hup, other bool
		if err := raw.Control(func(fd uintptr) {
			fds := []unix.PollFd{{Fd: int32(fd)}}
			n, err := unix.Poll(fds, 250)
			if err != nil || n == 0 {
				return
			}
			hup = fds[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0
			other = !hup
		}); err != nil {
			return // conn closed
		}
		if hup {
			cancel()
			return
		}
		if other { // e.g. POLLNVAL: do not spin
			time.Sleep(250 * time.Millisecond)
		}
	}
}
