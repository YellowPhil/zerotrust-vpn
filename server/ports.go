package main

import "errors"

func allocatePorts(CRR *ConnectRequestResponse, index int) (err error) {
	var startPort uint16 = 0
	var endPort uint16 = 0
	for i := range PortToCoreMapping {
		if i < int(Config.StartPort) {
			continue
		}

		if PortToCoreMapping[i] == nil {
			continue
		}

		if PortToCoreMapping[i].Client == nil {
			PortToCoreMapping[i].Client = ClientCoreMappings[index]
			ClientCoreMappings[index].PortRange = PortToCoreMapping[i]
			startPort = PortToCoreMapping[i].StartPort
			endPort = PortToCoreMapping[i].EndPort
			break
		}
	}

	if startPort == 0 {
		return errors.New("No ports ")
	}

	CRR.StartPort = startPort
	CRR.EndPort = endPort
	return nil
}
