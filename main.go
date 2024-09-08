package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var key = []byte("secret")

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
	mux.HandleFunc("GET /refresh", server.refreshHandler)

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

func (s DBServer) tokensHandler(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	guid := r.PathValue("guid")

	refreshTokenString, err := createRefreshTokenString(ip)
	if err != nil {
		log.Fatal(err)
	}
	accessTokenString, err := createAccessTokenString(guid, ip)
	if err != nil {
		log.Fatal(err)
	}

	refreshHash, err := getRefreshHash(refreshTokenString)
	if err != nil {
		log.Fatal(err)
	}

	s.db.Exec(`INSERT INTO app_table (guid, ip, refreshHash) VALUES ($1, $2, $3) ON CONFLICT (guid) DO UPDATE SET ip=$2, refreshHash=$3`, guid, ip, refreshHash)

	setTokenCookies(w, refreshTokenString, accessTokenString)
	// ref, acc := getTokensFromCookies(w, r)
	// fmt.Println(ref, acc)
}

func getRefreshHash(tokenString string) ([]byte, error) {
	s := getTokenSignature(tokenString)
	return HashPassword(s)
}

func (s DBServer) refreshHandler(w http.ResponseWriter, r *http.Request) {
	refreshTokenString, accessTokenString := getTokensFromCookies(w, r)

	refreshToken, err := parseTokenString(refreshTokenString)
	if err != nil {
		log.Fatal(err)
	}
	accessToken, err := parseTokenString(accessTokenString)
	if err != nil {
		log.Fatal(err)
	}

	claimsIP := refreshToken.Claims.(jwt.MapClaims)["ip"].(string)
	claimsGUID := accessToken.Claims.(jwt.MapClaims)["guid"].(string)

	newRefreshTokenString, err := createRefreshTokenString(claimsIP)
	if err != nil {
		log.Fatal(err)
	}
	newAccessTokenString, err := createAccessTokenString(claimsGUID, claimsIP)
	if err != nil {
		log.Fatal(err)
	}

	reqIP := getIP(r)
	if claimsIP != reqIP {
		sendNotification()
	}

	row := s.db.QueryRow(`SELECT refreshHash FROM app_table WHERE ip=$1`, claimsIP)

	var refreshHash []byte
	err = row.Scan(&refreshHash)
	if err != nil {
		log.Fatal(err)
	}

	err = bcrypt.CompareHashAndPassword(refreshHash, []byte(getTokenSignature(string(refreshTokenString))))
	if err != nil {
		log.Fatal(err)
	}

	newRefreshHash, err := getRefreshHash(newRefreshTokenString)
	if err != nil {
		log.Fatal(err)
	}

	_, err = s.db.Exec(`UPDATE app_table SET ip=$1, refreshHash=$2 WHERE ip=$3`, reqIP, newRefreshHash, claimsIP)
	if err != nil {
		fmt.Println("asd")
		log.Fatal(err)
	}

	setTokenCookies(w, newRefreshTokenString, newAccessTokenString)
}

func getTokenSignature(TokenString string) string {
	arr := strings.Split(TokenString, ".")
	return arr[2]
}

func sendNotification() {

}

func setTokenCookies(w http.ResponseWriter, refreshToken, accessToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:  "refreshToken",
		Value: refreshToken,
		Path:  "/",
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "accessToken",
		Value: accessToken,
		Path:  "/",
	})
}

func getTokensFromCookies(w http.ResponseWriter, r *http.Request) (string, string) {
	refreshTokenString := getCookieValue(w, r, "refreshToken")
	accessTokenString := getCookieValue(w, r, "accessToken")

	return refreshTokenString, accessTokenString
}

func getCookieValue(w http.ResponseWriter, r *http.Request, cookieName string) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
		}
		w.WriteHeader(http.StatusBadRequest)
		log.Fatal(err)
	}
	return c.Value
}

func createRefreshTokenString(ip string) (string, error) {
	refreshTokenExpirationTime := time.Now().Add(5 * time.Minute).Unix()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// "guid": id,
		"ip":  ip,
		"exp": refreshTokenExpirationTime,
	})
	return refreshToken.SignedString(key)
}

func createAccessTokenString(guid, ip string) (string, error) {
	accessTokenExpirationTime := time.Now().Add(2 * time.Minute).Unix()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"guid": guid,
		"ip":   ip,
		// "refreshTokenBase64": refreshTokenBase64,
		"exp": accessTokenExpirationTime,
	})
	return accessToken.SignedString(key)
}

func HashPassword(password string) ([]byte, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return hashedPassword, err
}

func parseTokenString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(string(tokenString), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	return token, err
}

func getIP(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
