package common

import "time"

type ScanConfig struct {
	Protocol string
	Target   string
	Timeout  time.Duration
}
