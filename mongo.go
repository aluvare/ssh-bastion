package main

import (
	"log"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type User struct {
	Name    string   `bson:"name"`
	Acl   string   `bson:"acl"`
	Authorized_keys string `bson:"authorized_keys"`
	Idrsa_key   string   `bson:"idrsa_key"`
}
type Server struct {
        Name    string   `bson:"name"`
        LoginUser   string   `bson:"login_user"`
        ConnectPath   string   `bson:"connect_path"`
	HostPubKeyFiles   []string `bson:"host_pubkeys"`
}
type Group struct {
	Acl    string   `bson:"acl"`
	Allow_list   []string   `bson:"allow_list"`
}

func getUser(s *mgo.Session, u string) (User) {
	session := s.Copy()
	defer session.Close()
	c := session.DB("sshbastion").C("users")
	var user User
	err := c.Find(bson.M{"name": u}).One(&user)
	if err != nil {
		log.Println("Failed to get user:", err)
	}
	return user
}
func getAcl(s *mgo.Session, a string) (Group) {
	session := s.Copy()
	defer session.Close()
	c := session.DB("sshbastion").C("groups")
	var group Group
	err := c.Find(bson.M{"acl": a}).One(&group)
	if err != nil {
		log.Println("Failed to get act:", err)
	}
	return group
}
func getServer(s *mgo.Session,sr string) (Server) {
	session := s.Copy()
	defer session.Close()
	c := session.DB("sshbastion").C("servers")
	var server Server
	err := c.Find(bson.M{"name": sr}).One(&server)
	if err != nil {
		log.Println("Failed to get server:", err)
	}
	return server
}
