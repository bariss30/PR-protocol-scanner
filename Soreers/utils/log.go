package utils

import "fmt"

var (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	White  = "\033[97m"
	Gray   = "\033[90m"
)

// PrintError yazdırır
func PrintError(format string, a ...interface{}) {
	fmt.Printf("%s[-] %s%s\n", Red, fmt.Sprintf(format, a...), Reset)
}

// PrintSuccess yazdırır
func PrintSuccess(format string, a ...interface{}) {
	fmt.Printf("%s[+] %s%s\n", Green, fmt.Sprintf(format, a...), Reset)
}

// PrintInfo yazdırır
func PrintInfo(format string, a ...interface{}) {
	fmt.Printf("[*] %s\n", fmt.Sprintf(format, a...))
}
