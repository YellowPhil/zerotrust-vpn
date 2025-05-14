package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"math"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jackpal/gateway"
	"github.com/yellowphil/zerotrust-vpn/certs"
	"github.com/yellowphil/zerotrust-vpn/iptables"
	"github.com/yellowphil/zerotrust-vpn/setcap"
	"golang.org/x/net/quic"

	"github.com/rs/zerolog/log"
)

func loadPublicSigningCert() (err error) {
	pubKeyBlock, _ := pem.Decode([]byte(certs.ControllerSigningCert))
	publicSigningCert, err = x509.ParseCertificate(pubKeyBlock.Bytes)
	if err != nil {
		return err
	}
	publicSigningKey = publicSigningCert.PublicKey.(*rsa.PublicKey)

	return
}

var (
	id              string
	interfaceIP     string
	config          bool
	features        string
	defaultHostname string
	enabledFeatures []string
	disableLogs     bool

	VPLEnabled bool = false
	VPNEnabled bool = false
	DNSEnabled bool = false
	APIEnabled bool = false
)

const (
	VPNFeature string = "VPN"
	VPLFeature string = "VPL"
	DNSFeature string = "DNS"
	APIFeature string = "API"
)

func isFeatureEnabled(feature string) bool {
	return slices.Contains(enabledFeatures, feature)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.StringVar(&id, "id", "", "ID")
	flag.StringVar(&interfaceIP, "interfaceIP", "", "InterfaceIP used when generating config and certificates")
	flag.BoolVar(&config, "config", false, "Generate config")
	flag.StringVar(&features, "features", "", "Select features. (VPN,VPL,API)")
	flag.StringVar(&defaultHostname, "hostname", "", "Main domain for DHCP")
	flag.BoolVar(&disableLogs, "nologs", false, "Disable logs")
	flag.Parse()

	if config {
		makeConfigAndCertificates()
		os.Exit(1)
	}

	enabledFeatures = strings.Split(features, ",")
	if len(features) == 0 {
		log.Fatal().Msg("no feature specified")
	}

	var err error
	Config, err = GetServerConfig(serverConfigPath)
	if err != nil {
		log.Fatal().Err(err)
	}

	for i := range enabledFeatures {
		switch enabledFeatures[i] {
		case APIFeature:
			APIEnabled = true
		case VPNFeature:
			VPNEnabled = true
		case VPLFeature:
			VPLEnabled = true
			if Config.VPL == nil {
				log.Fatal().Msg("no VPL settings")
			}
		case DNSFeature:
			DNSEnabled = true
		default:
			os.Exit(0)
		}
	}

	if VPNEnabled {
		initializeVPN()
	}

	if VPLEnabled {
		initializeVPL()
	}

	if Config.UserMaxConnections < 1 {
		Config.UserMaxConnections = 2
	}

	initializeCertsAndTLSConfig()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	// GENERIC ROUTINES
	SignalMonitor <- NewSignal(ctx, 1)
	SignalMonitor <- NewSignal(ctx, 2)
	SignalMonitor <- NewSignal(ctx, 3)
	SignalMonitor <- NewSignal(ctx, 4)
	SignalMonitor <- NewSignal(ctx, 5)

	if VPNEnabled {
		SignalMonitor <- NewSignal(ctx, 10)
		SignalMonitor <- NewSignal(ctx, 11)
		SignalMonitor <- NewSignal(ctx, 12)
	}

	if VPLEnabled {
		SignalMonitor <- NewSignal(ctx, 20)
		SignalMonitor <- NewSignal(ctx, 21)
		SignalMonitor <- NewSignal(ctx, 22)
	}

	for {
		select {
		case signal := <-quit:

			cancel()
			log.Warn().Msgf("EXIT %v", signal)
			return

		case index := <-toUserChannelMonitor:
			go toUserChannel(index)
		case index := <-fromUserChannelMonitor:
			go fromUserChannel(index)

		case SIGNAL := <-SignalMonitor:
			switch SIGNAL.ID {
			case 1:
				go pingActiveUsers(SIGNAL)
			case 2:
				go ControlSocketListener(SIGNAL)
			case 3:
				go DataSocketListener(SIGNAL)
			case 4:
				go startAPI(SIGNAL)
			case 5:
				go ReloadConfig(SIGNAL)

			// VPN
			case 10:
				go ExternalUDPListener(SIGNAL)
			case 11:
				go ExternalTCPListener(SIGNAL)
			case 12:

			// VPL
			case 20:
			case 21:
			case 22:

			}
		}
	}
}

func ReloadConfig(SIGNAL *SIGNAL) {
	defer RecoverAndReturnID(SIGNAL, 30)
	newConf, err := GetServerConfig(serverConfigPath)
	if err != nil {
		log.Fatal().Msgf("config error: %v", err)
	}
	if newConf != nil {
		Config = newConf
	}
}

func initializeVPN() {
	err := setcap.CheckCapabilities()
	if err != nil {
		log.Fatal().Msgf("no cap: %v", err)
	}

	err, _ = iptables.SetIPTablesRSTDropFilter(Config.InterfaceIP)
	if err != nil {
		log.Fatal().Msgf("iptables error: %v", err)
	}

	InterfaceIP = net.ParseIP(Config.InterfaceIP)
	if InterfaceIP == nil {
		log.Fatal().Msg("Cannot parse IP")
	}
	InterfaceIP = InterfaceIP.To4()

	_, _, err = createRawTCPSocket()
	if err != nil {
		panic(err)
	}
	_, _, err = createRawUDPSocket()
	if err != nil {
		panic(err)
	}

	GeneratePortAllocation()
	GenerateVPLCoreMappings()
}

func initializeVPL() (err error) {
	err = generateDHCPMap()
	if err != nil {
		return
	}

	if Config.VPL != nil {
		AllowAll = Config.VPL.AllowAll
	}
	return
}

func initializeCertsAndTLSConfig() {
	err := loadPublicSigningCert()
	if err != nil {
		panic(err)
	}

	controlCertificate, err = tls.LoadX509KeyPair(Config.ControlCert, Config.ControlKey)
	if err != nil {
		panic(err)
	}

	controlConfig = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.CurveP521},
		Certificates:     []tls.Certificate{controlCertificate},
	}

	quicConfig = &quic.Config{
		TLSConfig:                controlConfig,
		RequireAddressValidation: false,
		HandshakeTimeout:         time.Duration(10 * time.Second),
		KeepAlivePeriod:          0,
		MaxUniRemoteStreams:      500,
		MaxBidiRemoteStreams:     500,
		MaxStreamReadBufferSize:  70000,
		MaxStreamWriteBufferSize: 70000,
		MaxConnReadBufferSize:    70000,
		MaxIdleTimeout:           60 * time.Second,
	}
}

func makeConfigAndCertificates() {
	ep, err := os.Executable()
	if err != nil {
		log.Fatal().Err(err)
	}
	eps := strings.Split(ep, "/")
	ep = strings.Join(eps[:len(eps)-1], "/")
	ep += "/"

	if interfaceIP == "" {
		IFIP, err := gateway.DiscoverInterface()
		if err != nil {
			panic(err)
		}
		interfaceIP = IFIP.String()
	}

	if id != "" {
		sc := new(Server)
		sc.ControlIP = interfaceIP
		sc.InterfaceIP = interfaceIP
		sc.APIPort = "444"
		sc.ControlPort = "444"
		sc.DataPort = "443"
		sc.StartPort = 2000
		sc.EndPort = 65500
		sc.UserMaxConnections = 4
		sc.AvailableMbps = 1000
		sc.AvailableUserMbps = 10
		sc.InternetAccess = true
		sc.LocalNetworkAccess = true
		sc.DNSAllowCustomOnly = false
		sc.DNS = make([]*ServerDNS, 0)
		sc.Networks = make([]*ServerNetwork, 0)
		sc.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
		sc.ControlCert = ep + "server.crt"
		sc.ControlKey = ep + "server.key"

		N := new(ServerNetwork)
		N.Tag = "default"
		N.Network = interfaceIP + "/24"
		N.Nat = "10.10.10.1/24"
		sc.Networks = append(sc.Networks, N)

		sc.VPL = new(VPLSettings)
		sc.VPL.Network = new(ServerNetwork)
		sc.VPL.Network.Tag = "VPL"
		sc.VPL.Network.Network = "10.0.0.0/16"
		sc.VPL.Network.Nat = ""
		sc.VPL.Network.Routes = []*Route{
			{
				Address: "10.0.0.0/16",
				Metric:  "0",
			},
		}

		sc.VPL.MaxDevices = math.MaxUint16
		sc.VPL.AllowAll = true

		f, err := os.Create(ep + "server.json")
		if err != nil {
			panic(err)
		}
		defer f.Close()
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "    ")

		if err := encoder.Encode(sc); err != nil {
			log.Warn().Err(err)
		} else {
			log.Info().Msg("Config file read")
		}

	}

	_, err = certs.MakeCert(
		certs.ECDSA,
		ep+"server.crt",
		ep+"server.key",
		[]string{interfaceIP},
		[]string{""},
		"",
		time.Time{},
		true,
	)
	if err != nil {
		panic(err)
	}

	serialN, _ := certs.ExtractSerialNumberFromCRT(ep + "server.crt")
	log.Info().Msgf("Serial number: %v", serialN)
	f, err := os.Create(ep + "serial")
	if err != nil {
		panic("unable to create folder")
	}
	if f != nil {
		defer f.Close()
	}
	_, err = f.WriteString(serialN)
	if err != nil {
		panic("unable to write to file")
	}
}

func GenerateVPLCoreMappings() {
	VPLIPToCore[10] = make([][][]*UserCoreMapping, 11)
	VPLIPToCore[10][0] = make([][]*UserCoreMapping, 256)

	for ii := 0; ii < 256; ii++ {
		VPLIPToCore[10][0][ii] = make([]*UserCoreMapping, 256)

		for iii := 0; iii < 256; iii++ {
			VPLIPToCore[10][0][ii][iii] = nil
		}
	}
}

func GeneratePortAllocation() (err error) {
	slots = Config.AvailableMbps / Config.AvailableUserMbps
	portPerUser := (Config.EndPort - Config.StartPort) / slots

	currentPort := uint16(Config.StartPort)

	for uc := 0; uc < slots; uc++ {
		PR := new(PortRange)
		PR.StartPort = uint16(currentPort)
		PR.EndPort = PR.StartPort + uint16(portPerUser)

		for i := PR.StartPort; i <= PR.EndPort; i++ {

			if i < PR.StartPort {
				return errors.New("port is too small")
			} else if i > PR.EndPort {
				return errors.New("port is too big")
			}

			if PortToCoreMapping[i] != nil {
				if PortToCoreMapping[i].StartPort < PR.StartPort {
					return errors.New("port is too small")
				}
				if PortToCoreMapping[i].StartPort < PR.EndPort {
					return errors.New("port is too big")
				}
			}

			PortToCoreMapping[i] = PR
		}

		currentPort = PR.EndPort + 1
	}

	return nil
}
