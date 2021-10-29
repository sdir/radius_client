package main

import "github.com/sdir/eapol_test/session"

func main() {
	context := &session.Context{
		UserName:   "username",
		PassWord:   "password",
		NasAddr:    "192.168.111.111",
		NasPort:    "Ethernet0/0/4",
		NasPasswd:  "sercet",
		VlanID:     0,
		ClientAddr: "10.10.10.10",
		ClientMac:  "12:AB:AC:83:1D:12",
	}
	s := session.New("192.168.111.120", context)
	s.Run()
}
