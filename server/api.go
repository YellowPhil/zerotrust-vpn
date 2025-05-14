package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
)

func startAPI(signal *SIGNAL) {
	defer RecoverAndReturnID(signal, 1)

	mux := http.NewServeMux()
	registerHandlers(mux)

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	addr := fmt.Sprintf("%s:%s", Config.ControlIP, Config.APIPort)
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Printf("Failed to bind API server: %v", err)
		return
	}

	if err := server.ServeTLS(ln, Config.ControlCert, Config.ControlKey); err != nil {
		log.Printf("API server exited: %v", err)
	}
}

// Register API endpoints
func registerHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/", HTTP_HealthCheck)

	if VPLEnabled {
		mux.HandleFunc("/firewall", HTTP_Firewall)
	}
	if APIEnabled {
		mux.HandleFunc("/devices", HTTP_ListDevices)
	}
}

// Health check endpoint
func HTTP_HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_ = r.Body.Close()
}

// Validate API key from header
func HTTP_validateKey(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-API-KEY") != Config.APIKey {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// Handle /devices request
func HTTP_ListDevices(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if !HTTP_validateKey(w, r) {
		return
	}

	resp := &DeviceListResponse{
		Devices: make([]*listDevice, 0),
	}

outer:
	for _, mapping := range ClientCoreMappings {
		if mapping == nil {
			continue
		}

		if mapping.DHCP != nil {
			for _, d := range resp.Devices {
				if d.DHCP.Token == mapping.DHCP.Token {
					continue outer
				}
			}
		}

		device := &listDevice{
			AllowedIPs:   []string{},
			RAM:          mapping.RAM,
			CPU:          mapping.CPU,
			Disk:         mapping.Disk,
			Created:      mapping.Created,
			IngressQueue: len(mapping.ToUser),
			EgressQueue:  len(mapping.FromUser),
		}

		for _, host := range mapping.AllowedHosts {
			if host.Type != "auto" {
				device.AllowedIPs = append(device.AllowedIPs,
					fmt.Sprintf("%d-%d-%d-%d", host.IP[0], host.IP[1], host.IP[2], host.IP[3]))
			}
		}

		if mapping.DHCP != nil {
			resp.DHCPAssigned++
			device.DHCP = *mapping.DHCP
		}

		if mapping.PortRange != nil {
			device.StartPort = mapping.PortRange.StartPort
			device.EndPort = mapping.PortRange.EndPort
		}

		resp.Devices = append(resp.Devices, device)
	}

	resp.DHCPFree = len(DHCPMapping) - resp.DHCPAssigned

	for _, d := range resp.Devices {
		d.DHCP.Token = "redacted"
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, fmt.Sprintf("Encoding error: %s", err), http.StatusInternalServerError)
	}
}

type FirewallRequest struct {
	DHCPToken       string   `json:"DHCPToken"`
	IP              string   `json:"IP"`
	Hosts           []string `json:"Hosts"`
	DisableFirewall bool     `json:"DisableFirewall"`
}

// Handle /firewall request
func HTTP_Firewall(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req FirewallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Decoding error: %s", err), http.StatusInternalServerError)
		return
	}

	mapping := validateDHCPTokenAndIP(&req)
	if mapping == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if out := syncFirewallState(&req, mapping); len(out) > 0 {
		outBytes, err := json.Marshal(out)
		if err != nil {
			http.Error(w, fmt.Sprintf("Encoding error: %s", err), http.StatusInternalServerError)
			return
		}
		http.Error(w, string(outBytes), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}
