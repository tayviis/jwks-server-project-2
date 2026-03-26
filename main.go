package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "modernc.org/sqlite"
)

var db *sql.DB

// ================= DB INIT =================
func initDB() *sql.DB {
	database, err := sql.Open("sqlite", "./totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatal(err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	);`

	_, err = database.Exec(schema)
	if err != nil {
		log.Fatal(err)
	}

	return database
}

// ================= KEY HELPERS =================
func generateRSAKey() *rsa.PrivateKey {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return key
}

func pemEncode(key *rsa.PrivateKey) string {
	bytes := x509.MarshalPKCS1PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: bytes,
	}))
}

func pemDecode(str string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(str))
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

// ================= DB OPS =================
func insertKey(pemKey string, exp int64) int64 {
	res, err := db.Exec("INSERT INTO keys(key, exp) VALUES(?, ?)", pemKey, exp)
	if err != nil {
		log.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

// returns key + exp + kid
func getKey(expired bool) (string, int64, int64) {
	var key string
	var exp int64
	var kid int64

	if expired {
		db.QueryRow(`
			SELECT kid, key, exp 
			FROM keys 
			WHERE exp <= ? 
			LIMIT 1`,
			time.Now().Unix(),
		).Scan(&kid, &key, &exp)
	} else {
		db.QueryRow(`
			SELECT kid, key, exp 
			FROM keys 
			WHERE exp > ? 
			LIMIT 1`,
			time.Now().Unix(),
		).Scan(&kid, &key, &exp)
	}

	return key, exp, kid
}

// ================= JWKS =================
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT kid, key 
		FROM keys 
		WHERE exp > ?`,
		time.Now().Unix(),
	)
	if err != nil {
		http.Error(w, "db error", 500)
		return
	}
	defer rows.Close()

	type JWK struct {
		KID string `json:"kid"`
		KTY string `json:"kty"`
		ALG string `json:"alg"`
		USE string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	var keys []JWK

	for rows.Next() {
		var kid int64
		var pemKey string

		if err := rows.Scan(&kid, &pemKey); err != nil {
			http.Error(w, "scan error", 500)
			return
		}

		priv := pemDecode(pemKey)
		pub := &priv.PublicKey

		// IMPORTANT: correct JWKS encoding
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

		keys = append(keys, JWK{
			KID: fmt.Sprintf("%d", kid),
			KTY: "RSA",
			ALG: "RS256",
			USE: "sig",
			N:   n,
			E:   e,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": keys,
	})
}

// ================= AUTH =================
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}

	expired := r.URL.Query().Get("expired") == "true"

	pemKey, exp, kid := getKey(expired)
	priv := pemDecode(pemKey)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "userABC",
		"exp": exp,
	})

	token.Header["kid"] = fmt.Sprintf("%d", kid)

	signed, err := token.SignedString(priv)
	if err != nil {
		http.Error(w, "sign error", 500)
		return
	}

	w.Write([]byte(signed))
}

// ================= SEED KEYS =================
func seedKeys() {
	valid := generateRSAKey()
	expired := generateRSAKey()

	now := time.Now().Unix()

	insertKey(pemEncode(valid), now+3600)
	insertKey(pemEncode(expired), now-3600)
}

// ================= MAIN =================
func main() {
	db = initDB()
	log.Println("DB initialized")

	seedKeys()

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	log.Println("Listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
