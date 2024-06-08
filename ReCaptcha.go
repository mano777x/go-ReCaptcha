package ReCaptcha

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	regex = regexp.MustCompile(`"rresp","(.*?)"`)
)

func SolveCaptcha(url string) (string, error) {
	mTLSConfig := &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	mTLSConfig.MinVersion = tls.VersionTLS12
	mTLSConfig.MaxVersion = tls.VersionTLS12

	tr := &http.Transport{
		TLSClientConfig: mTLSConfig,
	}
	client := &http.Client{Transport: tr}
	params, err := parseUrl(url)
	if err != nil {
		return "", err
	}
	token, err := getRecaptchaToken(client, url)
	if err != nil {
		return "", err
	}
	data, err := getRecaptchaResponse(client, token, params)
	client.CloseIdleConnections()
	return data, err
}

func parseUrl(gurl string) (url.Values, error) {
	w, err := url.Parse(gurl)
	return w.Query(), err
}

func getRecaptchaToken(client *http.Client, url string) (string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	// chrome122
	req.Header.Set("authority", "www.google.com")
	req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("accept-language", "ru")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("sec-ch-ua", `"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-fetch-dest", "iframe")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "cross-site")
	req.Header.Set("upgrade-insecure-requests", "1")
	req.Header.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	r := regexp.MustCompile(`"recaptcha-token" value="(.*?)"`)
	g := r.FindSubmatch(bodyText)
	return string(g[1]), nil
}

func getRecaptchaResponse(client *http.Client, token string, params url.Values) (string, error) {
	dat, _ := url.ParseQuery("reason=q&hl=ru&size=invisible&chr=%5B89%2C64%2C27%5D&vh=13599012192")
	dat.Set("v", params.Get("v"))
	dat.Set("k", params.Get("k"))
	dat.Set("co", params.Get("co"))
	dat.Set("c", token)

	data := strings.NewReader(dat.Encode())
	req, _ := http.NewRequest("POST", "https://www.google.com/recaptcha/api2/reload?k="+params.Get("k"), data)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return regex.FindStringSubmatch(string(bodyText))[1], nil
}
