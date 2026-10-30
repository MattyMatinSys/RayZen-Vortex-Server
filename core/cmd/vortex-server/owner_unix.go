//go:build unix

package main

import (
	"os"
	"syscall"
)

type owner struct{ uid, gid int }

func statOwner(fi os.FileInfo) (owner, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return owner{}, false
	}
	return owner{int(st.Uid), int(st.Gid)}, true
}
