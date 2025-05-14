package main

import (
	"encoding/json"
	"math/rand"
	"os"
	"time"
)

func GetServerConfig(path string) (Server *Server, err error) {
	var nb []byte
	nb, err = os.ReadFile(path)
	if err != nil {
		return
	}
	err = json.Unmarshal(nb, &Server)
	return
}

var RAND_SOURCE = rand.NewSource(time.Now().UnixNano())

func CopySlice(in []byte) (out []byte) {
	out = make([]byte, len(in))
	_ = copy(out, in)
	return
}

// TODO .. make sure it's catching the context of the initiator
func RecoverAndReturnID(SIGNAL *SIGNAL, sleepTimeInSeconds int) {

	if SIGNAL.Ctx.Err() != nil {
		return
	}

	select {
	case <-SIGNAL.Ctx.Done():
		return
	default:
	}

	if sleepTimeInSeconds > 0 {
		time.Sleep(time.Duration(sleepTimeInSeconds) * time.Second)
	}

	SignalMonitor <- SIGNAL
}

var letterRunes = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
