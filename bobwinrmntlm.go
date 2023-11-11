package main

import (
	"context"
	"fmt"

	winrm "github.com/CalypsoSys/bobwinrm"
)

func main() {
	// winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	// use to fails with ==> func() winrm.Transporter { return &winrm.ClientNTLM{} },
	// now works with ==> winrm.NewEncryption("ntlm")
	//
	// using https/5986
	runExec("AllowUnencrypted_false_address", 5986, true, "username", "password")

	// winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	// should wortk with both
	//
	// using http/5985
	runExec("AllowUnencrypted_true_address", 5985, false, "username", "password") // works
}

func runExec(address string, port int, https bool, userName string, password string) {
	endpoint := winrm.NewEndpoint(address, port, https, true, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	enc, _ := winrm.NewEncryption("ntlm")
	params.TransportDecorator = func() winrm.Transporter { return enc }

	client, err := winrm.NewClientWithParameters(endpoint, userName, password, params)
	if err != nil {
		fmt.Println(err)
	}

	stdOut, stdErr, exitCode, err := client.RunCmdWithContext(context.Background(), "ipconfig /all")
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, stdOut, stdErr)
	if err != nil || (len(stdOut) == 0 && len(stdErr) > 0) {
		_ = exitCode
		fmt.Println(err)
	} else {
		fmt.Println("Command Test Ok")
	}

	wmiQuery := `select * from Win32_ComputerSystem`
	psCommand := fmt.Sprintf(`$FormatEnumerationLimit=-1;  Get-WmiObject -Query "%s" | Out-String -Width 4096`, wmiQuery)
	stdOut, stdErr, exitCode, err = client.RunPSWithContext(context.Background(), psCommand)
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, stdOut, stdErr)
	if err != nil || (len(stdOut) == 0 && len(stdErr) > 0) {
		_ = exitCode
		fmt.Println(err)
	} else {
		fmt.Println("PowerShell Test Ok")
	}
}
