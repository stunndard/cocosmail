package core

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/stunndard/go-maildir"
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
	mdPath := path.Join(d.dataPath, deliverTo)

	err = os.MkdirAll(mdPath, 0700)
	if err != nil {
		return false, err
	}

	md := maildir.Dir(mdPath)
	err = md.Init()
	if err != nil {
		return false, err
	}

	mdd, err := maildir.NewDelivery(mdPath)
	if err != nil {
		return false, errors.New(fmt.Sprintf("%s unable to create NewDelivery: %s", id, err))
	}

	written, err := mdd.Write(rawMsg.Bytes())
	if err != nil {
		return false, errors.New(fmt.Sprintf("%s unable to write to delivery: %s", id, err))
	}
	Logger.Info(fmt.Sprintf("%s written to maildir: %d bytes", id, written))

	err = mdd.Close()
	if err != nil {
		return false, errors.New(fmt.Sprintf("%s unable to close delivery: %s", id, err))
	}

	return false, nil
}
