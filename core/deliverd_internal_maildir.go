package core

import (
	"bytes"
	"fmt"
	"os"

	"github.com/stunndard/cocosmail/mailstore"
)

type DeliveryMaildir struct {
	dataPath string
}

func NewDeliveryMaildir(dataPath string) *DeliveryMaildir {
	return &DeliveryMaildir{
		dataPath: dataPath,
	}
}

func (d *DeliveryMaildir) GetName() string {
	return "maildir"
}

func (d *DeliveryMaildir) CheckConfig() (err error) {
	return os.MkdirAll(d.dataPath, 0700)
}

func (d *DeliveryMaildir) Deliver(id, deliverTo string, rawMsg *bytes.Buffer) (permFail bool, err error) {
	// get user
	usr, err := UserGetByLogin(deliverTo)
	if err != nil {
		return false, fmt.Errorf("cannot get user: %s", err)
	}
	if err := mailstore.Deliver(usr.HomePath(), rawMsg.Bytes()); err != nil {
		return false, fmt.Errorf("%s unable to write to maildir: %w", id, err)
	}
	Logger.Info(fmt.Sprintf("%s written to maildir: %d bytes", id, rawMsg.Len()))
	return false, nil
}
