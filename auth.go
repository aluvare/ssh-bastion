package main

import (
	"fmt"
	"log"
	"golang.org/x/crypto/ssh"
	ldap "github.com/tonnerre/go-ldap"
	"strings"
)

func AuthUserPass(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	perm := &ssh.Permissions{
		Extensions: map[string]string{
			"authType":	 "password",
			"password":	 string(password),
		},
	}
	var usr string
	if (strings.Contains(conn.User(), "#")) {
		rawuser := strings.Split(conn.User(), "#")
		usr = rawuser[0]
	} else {
		usr = conn.User()
	}
	if _, ok := config.Users[usr]; ! ok {
		return nil, fmt.Errorf("User Doesn't Exist in Config")
	}
	if string(password) == "" {
		// Blank password isn't handled properly by LDAP library, fail here.
		return nil, fmt.Errorf("Blank Password Not Allowed")
	}

	if config.Global.AuthType == "ad" {
		l, err := ldap.Dial("tcp", config.Global.LDAP_Server)
		if err != nil {
			log.Printf("LDAP Connect Failed: %s", err)
			return nil, fmt.Errorf("LDAP Connect Failed: %s", err)
		}

		if err := l.Bind(fmt.Sprintf("%s@%s", usr, config.Global.LDAP_Domain), string(password)); err != nil {
			log.Printf("LDAP Bind Failed: %s", err)
			return nil, fmt.Errorf("LDAP Bind Failed: %s", err)
		}

		return perm, nil
	} else {
		return nil, fmt.Errorf("No Valid Auth Types")
	}
}
