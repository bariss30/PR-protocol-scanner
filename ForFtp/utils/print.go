package utils

import (
	"fmt"
	"time"
)

// Print tipleri
const (
	INFO    = "INFO"
	SUCCESS = "SUCCESS"
	WARNING = "WARNING"
	ERROR   = "ERROR"
)

// PrintMessage evrensel çıktı fonksiyonu
func PrintMessage(level, message string) {
	var color string

	switch level {
	case INFO:
		color = Blue
	case SUCCESS:
		color = Green
	case WARNING:
		color = Yellow
	case ERROR:
		color = Red
	default:
		color = White
	}

	// Saat ekleyelim [2025-08-20 10:30:12] [INFO] Mesaj
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Printf("%s[%s] [%s] %s%s\n", color, timestamp, level, message, Reset)
}

// Pr evrensel çıktı fonksiyonu
func Pr(level, message string) string {
	var color string

	switch level {
	case "INFO":
		color = Blue
	case "SUCCESS":
		color = Green
	case "WARNING":
		color = Yellow
	case "ERROR":
		color = Red
	default:
		color = White
	}

	// Saatli formatlı çıktı döndürelim
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%s[%s] [%s] %s%s", color, timestamp, level, message, Reset)
}

const (
	ColorMagenta = "\033[35m" // ← Bunu ekle!
	ColorPurple  = "\033[35m" // ← Bunu ekle!

	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	Bold        = "\033[1m"
	ColorWhite  = "\033[37m" // ← bunu ekle!

)

func Colorize(text, color string) string {
	return color + text + ColorReset
}

func BoldText(text string) string {
	return Bold + text + ColorReset
}
func Print(s string) {
	fmt.Print(s)
}

func PrintBanner(msg string) {
	fmt.Println("╔════════════════════════════════════════╗")
	fmt.Println("║", msg)
	fmt.Println("╚════════════════════════════════════════╝")
}
