package main

import (
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"compress/gzip"
	"crypto/md5"
	"fmt"
	"github.com/Unknwon/goconfig"
	"github.com/boltdb/bolt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var authBucket = []byte("auth")
var newBucket = []byte("new")
var servedBucket = []byte("served")
var cacheBucket = []byte("cache")

const cookieName string = "parasoup-auth"

type Config struct {
	domain, port, listenPort, dataPath, username, password string
	db                                                     *bolt.DB
}

type Handler func(w http.ResponseWriter, r *http.Request)
type HandlerWrapper func(next Handler) Handler

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

func IsAssetHost(host string, config Config) bool {
	replaceString := GetReplacementString(config)
	r := regexp.MustCompile("asset-[^.]." + replaceString)
	return r.MatchString(host)
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
			if prev, ok := w.Header()[key]; ok {
				vals = append(vals, prev...)
			}
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

func IsSaveableType(contentType string) bool {
	commits := map[string]bool{
		"image/jpeg": true,
		"image/png":  true,
		"image/gif":  true,
	}
	_, ok := commits[contentType]
	return ok
}

func FileNameForPath(path string, config Config) string {
	path = strings.Replace(path, "/", "", -1)
	path = strings.Replace(path, ".", "", -1)
	return config.dataPath + "/" + path
}

func AttachEtag(w http.ResponseWriter, path string) {
	etag := fmt.Sprintf("\"%x\"", md5.Sum([]byte(path)))
	log.Println("etag:" + etag)
	w.Header()["ETag"] = []string{etag}
	w.Header()["Cache-Control"] = []string{fmt.Sprintf("max-age=%d", 60*60*24*365)}
}

func SendBinaryResponseForSoupResponse(w http.ResponseWriter, soupResponse *http.Response, path string, config Config) {
	for key, vals := range ConvertHeaderForResponse(soupResponse.Header, path, config) {
		w.Header()[key] = vals
	}

	log.Println("Parasoup Response:", w.Header())

	w.WriteHeader(soupResponse.StatusCode)
	AttachEtag(w, path)

	var targetWriter io.Writer
	targetWriter = w

	shouldWriteToFile := IsSaveableType(soupResponse.Header.Get("Content-Type")) && soupResponse.StatusCode == 200
	var targetFileName string
	if shouldWriteToFile {
		targetFileName = FileNameForPath(path, config)
		targetFile, err := os.Create(targetFileName)
		if err != nil {
			panic(err)
		}
		targetWriter = io.MultiWriter(w, targetFile)
	}

	var copyErr error
	if soupResponse.Header.Get("Content-Encoding") == "gzip" {
		gw := gzip.NewWriter(targetWriter)
		_, copyErr = io.Copy(gw, soupResponse.Body)
		gw.Flush()
	} else {
		_, copyErr = io.Copy(targetWriter, soupResponse.Body)
	}

	if shouldWriteToFile && copyErr != nil {
		os.Remove(targetFileName)
	}
}

func handler(config Config) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("Handler")
		log.Println("Path: ", r.Host)

		defer r.Body.Close()
		originalRequestData, err := ioutil.ReadAll(r.Body)

		if err != nil {
			panic(err)
			return
		}

		newRequestUrl := ReplaceParasoupWithSoupHost(GetSchemeForPath(r.URL.Path)+r.Host+r.URL.String(), r.URL.Path, config)
		soupRequest, err := http.NewRequest(r.Method, newRequestUrl, bytes.NewReader(originalRequestData))

		if err != nil {
			panic(err)
		}

		soupRequest.Header = ConvertHeaderForRequest(r.Header, r.URL.Path, config)

		log.Println("Original:", r.Method, r.Host+r.URL.String())
		log.Println("Soup Request:", r.Method, newRequestUrl)
		response, err := http.DefaultTransport.RoundTrip(soupRequest)

		if err != nil {
			panic(err)
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
}

func CookieValid(cookie string, config Config) bool {
	cookieValid := false
	err := config.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(authBucket)
		v := b.Get([]byte(cookie))
		cookieValid = v != nil
		return nil
	})
	return err == nil && cookieValid
}

func WrapDiskCache(next Handler, config Config) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		cachedFileName := FileNameForPath(r.URL.Path, config)
		stat, err := os.Stat(cachedFileName)
		if err == nil && stat.Size() == 0 {
			log.Println("Removing zero size file:" + cachedFileName)
			os.Remove(cachedFileName)
		} else if err == nil && !stat.IsDir() {
			log.Println("Read cached file:" + cachedFileName)

			w.Header()["Content-Length"] = []string{fmt.Sprintf("%d", stat.Size())}
			AttachEtag(w, r.URL.Path)

			reader, err := os.Open(cachedFileName)

			if err != nil {
				panic("Error reading file:" + cachedFileName)
			}

			io.Copy(w, reader)
			return
		}

		next(w, r)
	}
}

func WrapETagAsset(next Handler, config Config) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		val, ok := r.Header["If-None-Match"]
		if IsAssetHost(r.Host, config) && ok && len(val) > 0 {
			w.Header()["Cache-Control"] = []string{fmt.Sprintf("max-age=%d", 60*60*24*365)}
			w.WriteHeader(304)
		} else {
			next(w, r)
		}
	}
}

func WrapAuth(next Handler, config Config) Handler {
	return func(w http.ResponseWriter, r *http.Request) {
		authenticated := false

		if cookie, err := r.Cookie(cookieName); err == nil && CookieValid(cookie.Value, config) {
			authenticated = true
		}

		if user, password, ok := r.BasicAuth(); ok && user == config.username && password == config.password {
			newUUID := uuid.NewRandom().String()
			err := config.db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket(authBucket)
				err := b.Put([]byte(newUUID), []byte("ok"))
				return err
			})

			if err != nil {
				panic(err)
			}

			newCookie := new(http.Cookie)
			newCookie.Name = cookieName
			newCookie.Value = newUUID
			newCookie.Domain = "parasoup.de"
			newCookie.MaxAge = 60 * 60 * 24 * 365
			newCookie.Path = "/"

			http.SetCookie(w, newCookie)
			authenticated = true
		}

		if authenticated || IsAssetHost(r.Host, config) {
			next(w, r)
		} else {
			w.Header()["WWW-Authenticate"] = []string{"Basic realm=\"parasoup\""}
			w.WriteHeader(401)
		}
	}
}

func ReadConfig(fileName string) Config {
	cfg, err := goconfig.LoadConfigFile(fileName)
	if err != nil {
		panic(err)
	}

	domain, err := cfg.GetValue("http", "domain")
	if err != nil {
		panic(err)
	}

	port, err := cfg.GetValue("http", "port")
	if err != nil {
		panic(err)
	}

	listenPort, err := cfg.GetValue("http", "listenPort")
	if err != nil {
		panic(err)
	}

	dataPath, err := cfg.GetValue("storage", "dataPath")
	if err != nil {
		panic(err)
	}

	username, err := cfg.GetValue("http", "username")
	if err != nil {
		panic(err)
	}

	password, err := cfg.GetValue("http", "password")
	if err != nil {
		panic(err)
	}

	return Config{
		domain:     domain,
		port:       port,
		listenPort: listenPort,
		username:   username,
		password:   password,
		dataPath:   dataPath}

}

func main() {
	if len(os.Args) < 2 {
		panic("No config file given")
	}

	configFile := os.Args[1]

	db, err := bolt.Open("gosoup.db", 0600, nil)
	if err != nil {
		panic(err)
	}

	defer db.Close()

	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(authBucket)
		if err != nil {
			panic(err)
		}

		_, err = tx.CreateBucketIfNotExists(servedBucket)
		if err != nil {
			panic(err)
		}

		_, err = tx.CreateBucketIfNotExists(newBucket)
		if err != nil {
			panic(err)
		}

		_, err = tx.CreateBucketIfNotExists(cacheBucket)
		if err != nil {
			panic(err)
		}
		return nil
	})

	config := ReadConfig(configFile)

	config.db = db

	log.Println("Startup for " + config.domain + ":" + config.port + " on port " + config.listenPort)
	http.HandleFunc(
		"/",
		WrapAuth(
			WrapETagAsset(
				WrapDiskCache(
					handler(config),
					config),
				config),
			config))
	http.ListenAndServe(":"+config.listenPort, nil)
}
