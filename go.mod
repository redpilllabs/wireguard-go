module github.com/redpilllabs/wireguard-go

go 1.20

require (
	github.com/sagernet/sing v0.5.0-beta.1
	golang.org/x/crypto v0.25.0
	golang.org/x/net v0.27.0
	golang.org/x/sys v0.25.0
)

retract (
	v0.0.4
	v0.0.3
	v0.0.2
	v0.0.1
)
