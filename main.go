package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	tm2rabbit "github.com/CortexTechnology/tm2-rabbit-base"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

func main() {
	config := GetConfig()

	var publicKey = []byte(fmt.Sprintf(
		"-----BEGIN RSA PUBLIC KEY-----\n%s\n-----END RSA PUBLIC KEY-----",
		config.App.AuthPublicKey,
	))

	rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
	if err != nil {
		log.Fatal("Decode public key error: ", err.Error())
	}

	service := tm2rabbit.NewService(config.RabbitMq).Build()
	go service.Start()

	gqlRequestHandler := func(response http.ResponseWriter, request *http.Request) {
		log.Println("Request received:")
		requestTime := time.Now()

		authToken := request.Header.Get("Authorization")

		token := parseToken(rsaPublicKey, authToken)
		if token == nil || !token.Valid {
			log.Println("Bad token")
			response.WriteHeader(http.StatusUnauthorized)
			return
		}

		claims, _ := token.Claims.(jwt.MapClaims)
		profile := claims["tm2_profile"].(map[string]interface{})
		userIdString := profile["id"].(string)

		if request.Method != http.MethodPost {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		lock := make(chan struct{})

		requestBody, _ := ioutil.ReadAll(request.Body)

		cbk := func(result json.RawMessage, errResult json.RawMessage) error {

			log.Printf("response received")

			if errResult != nil {
				response.WriteHeader(http.StatusBadRequest)
				_, _ = response.Write(errResult)
			} else {
				resultStruct := &struct {
					Success bool
					Data    json.RawMessage
				}{}
				_ = json.Unmarshal(result, resultStruct)

				if resultStruct.Success {
					_, _ = response.Write(result)
				} else {

					errorsResponse := struct {
						Errors []struct{ Message json.RawMessage }
					}{Errors: []struct{ Message json.RawMessage }{
						{Message: resultStruct.Data},
					}}

					errorResponse, _ := json.Marshal(errorsResponse)
					_, _ = response.Write(errorResponse)
				}

			}

			close(lock)
			return nil
		}

		userId, _ := strconv.Atoi(userIdString)

		err := service.SendRequest("TM2Web", int64(userId), "GRAPHQL_REQUEST", json.RawMessage(requestBody), cbk)

		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			_, _ = response.Write([]byte(err.Error()))
			close(lock)
		}

		timeout := time.After(5 * time.Second)

	WaitLoop:
		for {
			select {
			case <-timeout:
				response.WriteHeader(http.StatusGatewayTimeout)
				break WaitLoop

			case <-lock:
				break WaitLoop
			}
		}

		log.Printf("Request finished: %v ms", (time.Now().UnixNano()-requestTime.UnixNano())/1000000)
	}

	http.HandleFunc("/graphql", gqlRequestHandler)
	err = http.ListenAndServe(":8070", nil)
	if err != nil {
		panic(err)
	}

}

func parseToken(publicKey *rsa.PublicKey, bearerToken string) *jwt.Token {
	tokenRegexp := regexp.MustCompile("Bearer (.*)")
	submatch := tokenRegexp.FindStringSubmatch(bearerToken)
	if len(submatch) != 2 {
		log.Println("Token is not bearer")
		return nil
	}

	tokenString := submatch[1]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v ", token.Header["alg"])
		}

		return publicKey, nil
	})

	if err != nil {
		log.Println("Token error: ", err.Error())
	}

	return token
}
