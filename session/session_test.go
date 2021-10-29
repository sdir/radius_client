package session

import (
	"net"
	"testing"
)

func TestSession_Send(t *testing.T) {
	type fields struct {
		ServerIP net.UDPAddr
		context  *Context
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "test",
			fields: fields{
				ServerIP: net.UDPAddr{
					IP:   nil,
					Port: 0,
					Zone: "",
				},
				context: &Context{
					UserName:   "",
					NasAddr:    "",
					NasPort:    "",
					NasPasswd:  "",
					VlanID:     0,
					ClientAddr: "",
					ClientMac:  "",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				ServerIP: tt.fields.ServerIP,
				context:  tt.fields.context,
			}
			s.Run()
		})
	}
}
