package main

import (
	"time"

	"golang.org/x/sys/unix"
)

func GetRealTimestamp(timeNanosec int64) (time.Time, error) {
	// 現在時刻・現在のboot offsetを取得し、boot_offset時の時刻を計算する
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return time.Time{}, err
	}
	offset := time.Nanosecond * time.Duration(now.Nano()-timeNanosec)
	return time.Now().Add(-1 * offset), nil
}
