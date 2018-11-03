package main

import (
	"os"
	//"fmt"
	"log"
	"strings"
	"io/ioutil"
	"github.com/jessevdk/go-flags"
	"gopkg.in/mgo.v2"
)

var config *SSHConfig
var msession *mgo.Session

var opts struct {
	Config	  string	  `short:"c" long:"config" description:"Configuration YAML file location" required:"true"`
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	if _, err := os.Stat(opts.Config); err != nil {
		log.Fatalf("Specified config file doesn't exist!\n")
	}

	config, err = fetchConfig(opts.Config)
	if err != nil {
		panic(err)
	}
	msession, err = mgo.Dial(config.Global.MongoURL)
	if err != nil {
		panic(err)
	}
	s, err := NewSSHServer()
	if err != nil {
		panic(err)
	}

	s.ListenAndServe(config.Global.ListenPath)
}

func GetMOTD() (string) {
	if len(config.Global.MOTDPath) > 0 {
		str, err := ioutil.ReadFile(config.Global.MOTDPath)
		if err != nil {
			log.Printf("Error reading MOTD file (%s): %s", config.Global.MOTDPath, err)
			return ""
		} else {
			return strings.Replace(string(str), "\n", "\r\n", -1)
		}
	} else {
		return ""
	}
}

func WriteAuthLog(format string, v ...interface{}) {
	log.Printf(format)
}
