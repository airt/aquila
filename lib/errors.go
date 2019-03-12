package lib

import (
	"errors"
)

func NewVersionNotSupportedError() error {
	return errors.New("VERSION NOT SUPPORTED")
}

func NewCommandNotSupportedError() error {
	return errors.New("COMMAND NOT SUPPORTED")
}

func NewAddressTypeNotSupportedError() error {
	return errors.New("ADDRESS TYPE NOT SUPPORTED")
}
