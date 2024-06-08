package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/mano777/go-ReCaptcha"
)

func main() {
	tok, err := ReCaptcha.SolveCaptcha("https://www.google.com/recaptcha/api2/anchor?ar=1&k=6LcR_okUAAAAAPYrPe-HK_0RULO1aZM15ENyM-Mf&co=aHR0cHM6Ly9hbnRjcHQuY29tOjQ0Mw..&hl=ru&v=YurWEBlMIwR4EqFPncmQTkxQ&size=invisible&cb=6p12nephmya4")
	if err != nil {
		log.Fatal(err)
	}
	client := &http.Client{}
	var data = strings.NewReader(`{"g-recaptcha-reponse":"` + tok + `"}`)
	req, err := http.NewRequest("POST", "https://ar1n.xyz/recaptcha3ScoreTest", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", bodyText)
}
