package main

import (
	"log"
	"os"
	"sync"
	"syscall"
	"time"
)

//go:noinline
func info(i int) (pid int, tid int, pid2 int, tid2 int) {
	log.Println("Info:", i)
	pid = os.Getpid()
	tid = syscall.Gettid()
	time.Sleep(100 * time.Millisecond)
	pid2 = os.Getpid()
	tid2 = syscall.Gettid()
	return pid, tid, pid2, tid2
}

type ptmapEntry struct {
	pid1 int
	tid1 int
	pid2 int
	tid2 int
}

func main() {
	wg := &sync.WaitGroup{}

	ptmapLock := sync.Mutex{}
	ptmap := make(map[int]ptmapEntry)

	count := 2

	for i := range count {
		wg.Go(func() {
			pid1, tid1, pid2, tid2 := info(i)
			info(i)
			ptmapLock.Lock()
			defer ptmapLock.Unlock()
			ptmap[i] = ptmapEntry{pid1, tid1, pid2, tid2}
		})
	}

	wg.Wait()

	for i := range count {
		entry := ptmap[i]
		log.Printf("Goroutine %d - PID1: %d, TID1: %d, PID2: %d, TID2: %d\n", i, entry.pid1, entry.tid1, entry.pid2, entry.tid2)
	}
}
