//go:build !linux

package device

import (
	"github.com/redpilllabs/wireguard-go/conn"
	"github.com/redpilllabs/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
