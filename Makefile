
all:
	go build cmd/eapol.go

linux:
	GOOS=linux GOARCH=amd64 go build -o eapol_linux -ldflags="-w -s" cmd/eapol.go
	upx eapol_linux
