package clock

import "time"

func Normalize(t time.Time) time.Time {
	return t.UTC().Truncate(1 * time.Second)
}
