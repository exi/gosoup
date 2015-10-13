package main

import (
	"bytes"
	"compress/gzip"
	"github.com/Unknwon/goconfig"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type Config struct {
	domain, port string
}

func IsHTTPSPath(path string) bool {
	if path == "/login" {
		return true
	} else {
		return false
	}
}

func GetReplacementString(config Config) string {
	replaceString := config.domain
	if config.port != "80" {
		replaceString = replaceString + ":" + config.port
	}

	return replaceString
}

func ReplaceParasoupWithSoupHost(s string, path string, config Config) string {
	replaceString := GetReplacementString(config)

	if IsHTTPSPath(path) {
		r := regexp.MustCompile("http://([^ ]*)" + replaceString)
		s = r.ReplaceAllString(s, "https://${1}soup.io")
	}

	r2 := regexp.MustCompile("http://(asset-[^.].)" + replaceString)
	s = r2.ReplaceAllString(s, "http://${1}soupcdn.com")
	s = strings.Replace(s, replaceString, "soup.io", -1)
	return s
}

func ReplaceSoupWithParasoupData(s string, path string, config Config) string {
	replaceString := GetReplacementString(config)

	r := regexp.MustCompile("https?://([^ '\"]*)soup.io")
	s = r.ReplaceAllString(s, "http://${1}"+replaceString)
	r2 := regexp.MustCompile("([^ '\"]*)soup.io")
	s = r2.ReplaceAllString(s, "${1}"+replaceString)
	s = strings.Replace(s, "soupcdn.com", replaceString, -1)
	return s
}

func ConvertHeaderForRequest(h http.Header, path string, config Config) http.Header {
	newHeader := http.Header{}

	for key, vals := range h {
		for _, val := range vals {
			newHeader.Add(key, ReplaceParasoupWithSoupHost(val, path, config))
		}
	}

	return newHeader
}

func ConvertHeaderForResponse(h http.Header, path string, config Config) http.Header {
	newHeader := http.Header{}

	for key, vals := range h {
		for _, val := range vals {
			if key == "Set-Cookie" {
				newHeader.Add(key, strings.Replace(val, "soup.io", config.domain, -1))
			} else {
				newHeader.Add(key, ReplaceSoupWithParasoupData(val, path, config))
			}
		}
	}

	return newHeader
}

func GetSchemeForPath(path string) string {
	if IsHTTPSPath(path) {
		return "http://"
	} else {
		return "http://"
	}
}

func SendTextResponseForSoupResponse(w http.ResponseWriter, soupResponse *http.Response, path string, config Config) {
	log.Println("Reading response")
	newResponseData, err := ioutil.ReadAll(soupResponse.Body)

	if err != nil {
		log.Println("Read error", err)
		return
	}

	newResponseData = []byte(ReplaceSoupWithParasoupData(string(newResponseData), path, config))

	for key, vals := range ConvertHeaderForResponse(soupResponse.Header, path, config) {
		if key != "Content-Length" {
			w.Header()[key] = vals
		}
	}

	log.Println("Parasoup Response:", w.Header())

	w.WriteHeader(soupResponse.StatusCode)

	if soupResponse.Header.Get("Content-Encoding") == "gzip" {
		gw := gzip.NewWriter(w)
		gw.Write(newResponseData)
		gw.Flush()
	} else {
		w.Write(newResponseData)
	}
}

func SendBinaryResponseForSoupResponse(w http.ResponseWriter, soupResponse *http.Response, path string, config Config) {
	for key, vals := range ConvertHeaderForResponse(soupResponse.Header, path, config) {
		w.Header()[key] = vals
	}

	log.Println("Parasoup Response:", w.Header())

	w.WriteHeader(soupResponse.StatusCode)

	if soupResponse.Header.Get("Content-Encoding") == "gzip" {
		gw := gzip.NewWriter(w)
		io.Copy(gw, soupResponse.Body)
		gw.Flush()
	} else {
		io.Copy(w, soupResponse.Body)
	}
}

func handler(w http.ResponseWriter, r *http.Request, config Config) {
	log.Println("Handler")
	log.Println("Path: ", r.Host)

	defer r.Body.Close()
	log.Println("Reading request")
	originalRequestData, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.Println("Read error", err)
		return
	}

	newRequestUrl := ReplaceParasoupWithSoupHost(GetSchemeForPath(r.URL.Path)+r.Host+r.URL.String(), r.URL.Path, config)
	soupRequest, err := http.NewRequest(r.Method, newRequestUrl, bytes.NewReader(originalRequestData))

	if err != nil {
		log.Println("Request creation error", err)
		return
	}

	log.Println("Filling soupRequest")
	soupRequest.Header = ConvertHeaderForRequest(r.Header, r.URL.Path, config)

	log.Println("Original:", r.Method, r.Host+r.URL.String(), r.Header)
	log.Println("Soup Request:", r.Method, newRequestUrl, soupRequest.Header)
	response, err := http.DefaultTransport.RoundTrip(soupRequest)

	if err != nil {
		log.Println("Request error", err)
		return
	}
	defer response.Body.Close()

	if response.Header.Get("Content-Encoding") == "gzip" {
		response.Body, err = gzip.NewReader(response.Body)
		if err != nil {
			panic(err)
		}
		defer response.Body.Close()
	}

	isTextType := false

	if val, ok := response.Header["Content-Type"]; ok {
		if matched, _ := regexp.MatchString("text/.*", val[0]); matched {
			isTextType = true
		}
	}

	if isTextType {
		SendTextResponseForSoupResponse(w, response, r.URL.Path, config)
	} else {
		SendBinaryResponseForSoupResponse(w, response, r.URL.Path, config)
	}
	log.Println("Request done")
}

func main() {
	configFile := os.Args[1]

	cfg, err := goconfig.LoadConfigFile(configFile)
	if err != nil {
		panic("Config file was not read")
	}

	domain, err := cfg.GetValue("http", "domain")
	if err != nil {
		panic("Could not get domain from config")
	}

	port, err := cfg.GetValue("http", "port")
	if err != nil {
		panic("Could not get port from config")
	}

	config := Config{domain: domain, port: port}

	log.Println("Startup for " + domain + ":" + port)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler(w, r, config)
	})
	http.ListenAndServe(":"+port, nil)
}
