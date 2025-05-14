package setcap

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/term"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func CheckCapabilities() (err error) {
	orig := cap.GetProc()
	defer orig.SetProc()

	var capabilities *cap.Set

	if capabilities, err = orig.Dup(); err != nil {
		return fmt.Errorf("failed to get capabilities, err: %s", err)
	}

	missingFlags := false
	for requiredCap := range []cap.Value{cap.NET_BIND_SERVICE, cap.NET_ADMIN, cap.NET_RAW} {
		if on, _ := capabilities.GetFlag(cap.Permitted, cap.Value(requiredCap)); !on {
			missingFlags = true
			break
		}
	}

	if !missingFlags {
		return
	}

	log.Println("Enter Password: ")

	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err == nil {
		password := string(bytePassword)
		cmd := exec.Command("sudo", "-S", "/usr/sbin/setcap", "cap_net_raw,cap_net_bind_service,cap_net_admin+eip", os.Args[0])
		cmd.Stdin = strings.NewReader(password + "\n")
		cmd.Stdout = os.Stdout
		err = cmd.Run()
		_ = exec.Command("sudo", "-kK")
		if err != nil {
			log.Println("Unable to setcap: ", err)
			log.Println("RUN: `sudo setcap 'cap_net_raw,cap_net_bind_service,cap_net_admin+eip' [BINARY]` in order to give it permissions to change and manage networks")
			log.Println("RUN: `sudo setcap 'cap_net_raw,cap_net_bind_service,cap_net_admin+eip' [BINARY]` in order to give it permissions to change and manage networks")
		} else {
			argv0, _ := exec.LookPath(os.Args[0])
			syscall.Exec(argv0, os.Args, os.Environ())
		}
		os.Exit(1)
	}
	return
}
