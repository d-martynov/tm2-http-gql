package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	tm2rabbit "github.com/CortexTechnology/tm2-rabbit-base"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type httpGqlService struct {
	rsaPublicKey *rsa.PublicKey
	tm2Service   tm2rabbit.Service
}

type graphqlResponse struct {
	Success bool
	Data    json.RawMessage
	Errors  []struct {
		Message json.RawMessage
	}
}

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
	httpGqlService := httpGqlService{rsaPublicKey: rsaPublicKey, tm2Service: service}

	go service.Start()
	httpGqlService.Start()
}

func (s httpGqlService) Start() {
	http.HandleFunc("/graphql", s.onGqlRequestReceived)

	if err := http.ListenAndServe(":8070", nil); err != nil {
		panic(err)
	}
}

func (s httpGqlService) onGqlRequestReceived(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	userId, err := s.getUserId(request.Header.Get("Authorization"))
	if err != nil {
		//userId = 4

		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(err.Error()))
		return
	}

	log.Println("Request received")
	requestTime := time.Now()

	var wg sync.WaitGroup
	wg.Add(1)

	isTimedOut := false
	timeoutTimer := time.NewTimer(5 * time.Second)
	go func() {
		<-timeoutTimer.C
		response.WriteHeader(http.StatusGatewayTimeout)
		isTimedOut = true
		wg.Done()
	}()

	requestBody, _ := ioutil.ReadAll(request.Body)

	err = s.tm2Service.SendRequest(
		"TM2Web",
		userId,
		"GRAPHQL_REQUEST",
		json.RawMessage(requestBody),
		func(result json.RawMessage, errResult json.RawMessage) error {
			if isTimedOut {
				return errors.New("Timed out response ")
			}

			defer wg.Done()

			var err error
			if errResult != nil {
				response.WriteHeader(http.StatusBadRequest)
				_, err = response.Write(errResult)
				return err
			}

			responseStruct := graphqlResponse{}
			_ = json.Unmarshal(result, &responseStruct)

			if responseStruct.Success {
				_, err = response.Write(result)
			} else {
				errorsResponse := graphqlResponse{
					Errors: []struct{ Message json.RawMessage }{{Message: responseStruct.Data}},
				}

				errorResponse, _ := json.Marshal(errorsResponse)
				_, err = response.Write(errorResponse)
			}

			return err
		})

	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte(err.Error()))
		wg.Done()
	}

	wg.Wait()
	timeoutTimer.Stop()

	log.Printf("Request finished: %v ms", (time.Now().UnixNano()-requestTime.UnixNano())/1000000)
}

func (s httpGqlService) getUserId(authToken string) (int64, error) {
	token, err := s.parseToken(authToken)
	if err != nil {
		return 0, err
	}

	if token == nil || !token.Valid {
		return 0, errors.New("Auth token is not valid ")
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	profile := claims["tm2_profile"].(map[string]interface{})
	userIdString := profile["id"].(string)

	userId, err := strconv.Atoi(userIdString)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("Get userId error: %s", err.Error()))
	}

	return int64(userId), nil
}

func (s httpGqlService) parseToken(bearerToken string) (*jwt.Token, error) {
	tokenRegexp := regexp.MustCompile("Bearer (.*)")
	submatch := tokenRegexp.FindStringSubmatch(bearerToken)
	if len(submatch) != 2 {
		return nil, errors.New("Token is not Bearer ")
	}

	tokenString := submatch[1]

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v ", token.Header["alg"])
		}

		return s.rsaPublicKey, nil
	})
}
