package clock

import (
	"time"
)

func Normalize(t time.Time) time.Time {
	return t.UTC().Truncate(1 * time.Second)
}

func SecondsUntil(t time.Time) int {
	return int(Normalize(t).Sub(Normalize(time.Now())).Seconds())
}

func InPast(t time.Time) bool {
	return Normalize(t).Before(Normalize(time.Now()))
}
