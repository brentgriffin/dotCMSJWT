package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"log"
	"os"
	"strings"
	"time"
)

var subject *string
var issuer *string
var secretFilename *string
var hmacSecret string
var decodedSecret []byte

func init() {
	subject = flag.String("s", "", "subject - The user id you are generating this token for")
	issuer = flag.String("i", "", "issuer - The id of the cluster you are generating the token for")
	secretFilename = flag.String("f", "secret.dat", "Name of file holding your JWT secret")
	flag.Parse()

	if len(*subject) == 0 {
		usage()
		log.Fatalln("ERROR - missing required subject (-s) option!")
	}
	if len(*issuer) == 0 {
		usage()
		log.Fatalln("ERROR - missing required issuer (-i) option!")
	}
}

func main() {
	var err error
	hmacSecret, err = getSecret(*secretFilename)
	if err != nil {
		usage()
	}
	checkFatal(err)

	decodedSecret, err = jwt.DecodeSegment(hmacSecret)
	checkFatal(err)

	tokenString, err := createToken(*subject, *issuer, decodedSecret)
	checkFatal(err)

	fmt.Println("tokenString = " + tokenString)
}

func usage() {
	var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fmt.Fprintf(CommandLine.Output(), "usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
}

func getSecret(filename string) (string, error) {
	var secret string
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 1 {
			secret = line
			break
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	if len(secret) < 1 {
		log.Fatalf("ERROR - unable to read secret from file: %s\n", filename)
	}
	return secret, nil
}

func createToken(subject string, issuer string, secret []byte) (string, error) {
	ts := time.Now()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"jti":        uuid.New(),
		"iat":        ts.Unix(),
		"updated_at": 1204824961000,
		"sub":        subject,
		"iss":        issuer})
	return token.SignedString(secret)
}

func checkFatal(e error) {
	if e != nil {
		panic(e)
	}
}
