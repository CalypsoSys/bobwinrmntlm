package main

import (
	"bytes"
	"context"
	"fmt"

	winrm "github.com/CalypsoSys/bobwinrm"
)

func main() {
	runExec("address", "username", "password") // fails
	runExec("address", "username", "password") // works
}

func runExec(address string, userName string, password string) {
	endpoint := winrm.NewEndpoint(address, 5985, false, false, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	//params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	enc, _ := winrm.NewEncryption("ntlm")
	params.TransportDecorator = func() winrm.Transporter { return enc }

	client, err := winrm.NewClientWithParameters(endpoint, userName, password, params)
	if err != nil {
		panic(err)
	}

	var outWriter, errWriter bytes.Buffer
	exitCode, err := client.RunWithContextWithInput(context.Background(), "ipconfig /all", &outWriter, &errWriter, nil)
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, outWriter.String(), errWriter.String())
}
