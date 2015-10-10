package main

import (
	"compress/gzip"
	"net/http"
	"log"
	"io/ioutil"
	"strings"
	"bytes"
	"regexp"
)

func IsHTTPSPath(path string) bool {
	if path == "/login" {
		return true
	} else {
		return false
	}
}

func ReplaceParasoupWithSoupHost(s  string, path string) string {
	if IsHTTPSPath(path) {
		r := regexp.MustCompile("http://([^ ]*)parasoup.de:8080")
		s = r.ReplaceAllString(s, "http://${1}soup.io")
	}
	return strings.Replace(s, "parasoup.de:8080", "soup.io", -1)
}

func ReplaceSoupWithParasoupData(s  string, path string) string {
	r := regexp.MustCompile("https?://([^ ]*)soup.io")
	r2 := regexp.MustCompile("([^ ]*)soup.io")
	s = r.ReplaceAllString(s, "http://${1}parasoup.de:8080")
	s = r2.ReplaceAllString(s, "${1}parasoup.de:8080")
	return s
}

func ConvertHeaderForRequest(h http.Header, path string) http.Header {
	newHeader := http.Header{}

	for key, vals := range h {
		for _, val := range vals {
			newHeader.Add(key, ReplaceParasoupWithSoupHost(val, path))
		}
	}

	return newHeader
}

func ConvertHeaderForResponse(h http.Header, path string) http.Header {
	newHeader := http.Header{}

	for key, vals := range h {
		for _, val := range vals {
			if key == "Set-Cookie" {
				newHeader.Add(key, strings.Replace(val, "soup.io", "parasoup.de", -1))
			} else {
				newHeader.Add(key, ReplaceSoupWithParasoupData(val, path))
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

func handler(w http.ResponseWriter, r *http.Request) {
	log.Println("Handler")
	log.Println("Path: ", r.Host)

	defer r.Body.Close()
	log.Println("Reading request")
	originalRequestData, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.Println("Read error", err)
		return
	}

	newRequestUrl := ReplaceParasoupWithSoupHost(GetSchemeForPath(r.URL.Path) + r.Host + r.URL.String(), r.URL.Path)
	soupRequest, err := http.NewRequest(r.Method, newRequestUrl, bytes.NewReader(originalRequestData))

	if err != nil {
		log.Println("Request creation error", err)
		return
	}

	log.Println("Filling soupRequest")
	soupRequest.Header = ConvertHeaderForRequest(r.Header, r.URL.Path)

	log.Println("Original:",r.Method, r.Host + r.URL.String(), r.Header)
	log.Println("Soup Request:",r.Method, newRequestUrl, soupRequest.Header)
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

	log.Println("Reading response")
	newResponseData, err := ioutil.ReadAll(response.Body)
	if val, ok := response.Header["Content-Type"]; ok {
		if matched, _ := regexp.MatchString("text/.*", val[0]); matched {
			newResponseData = []byte(ReplaceSoupWithParasoupData(string(newResponseData), r.URL.Path))
		}
	}

	if err != nil {
		log.Println("Read error", err)
		return
	}

	for key, vals := range ConvertHeaderForResponse(response.Header, r.URL.Path) {
		if key != "Content-Length" {
		    w.Header()[key] = vals
		}
	}
	log.Println("Parasoup Response:", w.Header())

	w.WriteHeader(response.StatusCode)

	if response.Header.Get("Content-Encoding") == "gzip" {
		gw := gzip.NewWriter(w)
		gw.Write(newResponseData)
		gw.Flush()
	} else {
		w.Write(newResponseData)
	}
	log.Println("Request done")
}

func main() {
	log.Println("Startup")
	http.HandleFunc("/", handler)
	http.ListenAndServe(":8080", nil)
}
