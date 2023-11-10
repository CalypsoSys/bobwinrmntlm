package main

import (
	"bytes"
	"context"
	"fmt"

	winrm "github.com/CalypsoSys/bobwinrm"
)

func main() {
	// winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	// use to fails with ==> func() winrm.Transporter { return &winrm.ClientNTLM{} },
	// now works with ==> winrm.NewEncryption("ntlm")
	runExec("AllowUnencrypted_false_address", "username", "password")

	// winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	// should wortk with both
	runExec("AllowUnencrypted_true_address", "username", "password") // works
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