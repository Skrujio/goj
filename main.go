package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	dbUser := "postgres"  // os.Getenv("POSTGRES_USER")
	dbPassword := "admin" // os.Getenv("POSTGRES_PASSWORD")
	dbName := "postgres"  // os.Getenv("POSTGRES_NAME")
	db, err := sql.Open("postgres",
		fmt.Sprintf("postgres://%s:%s@localhost:5432/%s?sslmode=disable",
			dbUser, dbPassword, dbName))
	if err != nil {
		fmt.Println(err)
	}

	defer db.Close()

	creatTable(db)

	server := DBServer{db}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /tokens/{guid}", server.tokensHandler)
	mux.HandleFunc("POST /refresh", server.refreshHandler)

	http.ListenAndServe(":8080", mux)
}

func creatTable(db *sql.DB) {
	query := `CREATE TABLE IF NOT EXISTS app_table (
		guid UUID PRIMARY KEY,
		ip INET,
		refreshHash CHAR(300))`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}

type DBServer struct {
	db *sql.DB
}

type Tokens struct {
	RefreshBase64 string
	Access        string
}

func (s DBServer) tokensHandler(w http.ResponseWriter, req *http.Request) {
	reqGUID := getGUID(req)
	reqIP := getIP(req)

	var dbIP string
	row := s.db.QueryRow(`SELECT ip FROM app_table WHERE guid=$1`, reqGUID)

	refreshTokenSignedString, err := createRefreshTokenSignedString(reqGUID, reqIP)
	if err != nil {
		log.Fatal(err)
	}

	// refreshTokenHash, err := HashPassword(refreshTokenSignedString)
	if err != nil {
		fmt.Print(len(refreshTokenSignedString))
		log.Fatal(err)
	}

	switch err := row.Scan(&dbIP); err {
	case sql.ErrNoRows:
		fmt.Println("ErrNoRows")
		_, err := s.db.Exec(`INSERT INTO app_table (guid, ip, refreshHash) VALUES ($1, $2, $3)`, reqGUID, reqIP, refreshTokenSignedString)
		fmt.Println(err)

	case nil:
		fmt.Println("nil")
		if reqIP != dbIP {
			s.db.Exec(`UPDATE app_table ip=$1 WHERE guid=$2`, reqIP, reqGUID)
		}

		s.db.Exec(`UPDATE app_table refreshHash=$1 WHERE guid=$2`, refreshTokenSignedString, reqGUID)
	default:
		log.Fatal(err)
	}

	refreshTokenBase64 := base64.StdEncoding.EncodeToString([]byte(refreshTokenSignedString))
	accessTokenSignedString, err := createAccessTokenSignedString(reqGUID, reqIP, base64.StdEncoding.EncodeToString([]byte(refreshTokenSignedString)))
	parseTokenString(accessTokenSignedString)
	if err != nil {
		log.Fatal(err)
	}

	err = json.NewEncoder(w).Encode(Tokens{
		refreshTokenBase64,
		accessTokenSignedString,
	})
	if err != nil {
		log.Fatal(err)
	}
}

func (s DBServer) refreshHandler(w http.ResponseWriter, req *http.Request) {
	var tokens Tokens
	err := json.NewDecoder(req.Body).Decode(&tokens)
	if err != nil {
		log.Fatal(err)
	}

	refreshTokenSignedString, err := base64.StdEncoding.DecodeString(tokens.RefreshBase64)
	if err != nil {
		log.Fatal(err)
	}

	refreshTokenClaims := parseTokenString(string(refreshTokenSignedString)).Claims.(jwt.MapClaims)

	// if int64(refreshTokenClaims["exp"].(float64)) < time.Now().Unix() {
	// 	log.Fatal(fmt.Errorf("refresh token is expired"))
	// }

	accessTokenClaims := parseTokenString(tokens.Access).Claims.(jwt.MapClaims)

	// if int64(accessTokenClaims["exp"].(float64)) < time.Now().Unix() {
	// 	log.Fatal(fmt.Errorf("access token is expired"))
	// }

	if refreshTokenClaims["guid"] != accessTokenClaims["guid"] || tokens.RefreshBase64 != accessTokenClaims["refreshTokenBase64"].(string) {
		log.Fatal(fmt.Errorf("invalid pair of tokens"))
	}

	reqGUID := refreshTokenClaims["guid"].(string)
	reqIP := getIP(req)

	var dbIP string
	var dbRefreshHash string
	err = s.db.QueryRow(`SELECT ip, refreshHash FROM app_table WHERE guid=$1`, reqGUID).Scan(&dbIP, &dbRefreshHash)
	if err != nil {
		log.Fatal(err)
	}

	if reqIP != dbIP {
		s.db.Exec(`UPDATE app_table ip=$1 WHERE guid=$2`, reqIP, reqGUID)
	}

	// err = bcrypt.CompareHashAndPassword([]byte(dbRefreshHash), refreshTokenSignedString)
	// if []byte(dbRefreshHash) != refreshTokenSignedString { // err != nil {
	// 	fmt.Println(dbRefreshHash)
	// 	// fmt.Println(refreshTokenSignedString)
	// 	fmt.Println("3")
	// 	log.Fatal(fmt.Errorf("mismatching refresh token"))
	// }

	refreshTokenBase64 := base64.StdEncoding.EncodeToString([]byte(refreshTokenSignedString))
	accessTokenSignedString, err := createAccessTokenSignedString(reqGUID, reqIP, base64.StdEncoding.EncodeToString([]byte(refreshTokenSignedString)))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(refreshTokenBase64)
	fmt.Println(accessTokenSignedString)

	err = json.NewEncoder(w).Encode(Tokens{
		refreshTokenBase64,
		accessTokenSignedString,
	})
	if err != nil {
		log.Fatal(err)
	}
}

func getGUID(r *http.Request) string {
	return r.PathValue("guid")
}

func getIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func createRefreshTokenSignedString(id, ip string) (string, error) {
	refreshTokenExpirationTime := time.Now().Add(5 * time.Minute).Unix()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": id,
		"ip":   ip,
		"iat":  refreshTokenExpirationTime,
	})
	return refreshToken.SignedString(key)
}

func createAccessTokenSignedString(id, ip, refreshTokenBase64 string) (string, error) {
	accessTokenExpirationTime := time.Now().Add(2 * time.Minute).Unix()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid":               id,
		"ip":                 ip,
		"refreshTokenBase64": refreshTokenBase64,
		"iat":                accessTokenExpirationTime,
	})
	return accessToken.SignedString(key)
}

func parseTokenString(tokenString string) *jwt.Token {
	token, err := jwt.Parse(string(tokenString), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		log.Fatal(err)
	}
	return token
}

var key = []byte("secret")

func HashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return hashedPassword, err
}
