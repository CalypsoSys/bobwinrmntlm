package main

import (
	"context"
	"fmt"

	winrm "github.com/CalypsoSys/bobwinrm"
)

const (
	COMMAND_TEST                           string = `select DNSHostName,Name,Manufacturer,Model,TotalPhysicalMemory,Domain,DomainRole from Win32_ComputerSystem`
	COMMAND_RESOURCES_HYPERV_PS_CPU_MEMORY string = `Get-VM -erroraction 'silentlycontinue' | Select Id, State, CPUUsage, MemoryDemand`
	SERVICE_TEST                           string = `select * from Win32_Service`
)

func main() {
	// winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	// use to fails with ==> func() winrm.Transporter { return &winrm.ClientNTLM{} },
	// now works with ==> winrm.NewEncryption("ntlm")
	//runExec("AllowUnencrypted_false_address", "username", "password")

	// winrm set winrm/config/service '@{AllowUnencrypted="true"}'
	// should wortk with both
	//runExec("AllowUnencrypted_true_address", "username", "password") // works

	runExec("10.92.11.109", 5986, true, "jasontest", "adm!nd42")

	runExec("10.90.9.25", 5985, false, "administrator", "adm!nd42")
	runExec("10.42.29.1", 5985, false, "device42.pvt\\administrator", "adm!nd42") // works?
	runExec("10.92.11.109", 5986, true, "administrator", "adm!nd42")              // works - allows unencrypted

}

func runExec(address string, port int, https bool, userName string, password string) {
	endpoint := winrm.NewEndpoint(address, port, https, true, nil, nil, nil, 0)

	params := winrm.DefaultParameters
	//params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
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
		fmt.Println("OK1")
	}

	psCommand := fmt.Sprintf(`$FormatEnumerationLimit=-1;  Get-WmiObject -Query "%s" | Out-String -Width 4096`, COMMAND_TEST)
	stdOut, stdErr, exitCode, err = client.RunPSWithContext(context.Background(), psCommand)
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, stdOut, stdErr)
	if err != nil || (len(stdOut) == 0 && len(stdErr) > 0) {
		_ = exitCode
		fmt.Println(err)
	} else {
		fmt.Println("OK2")
	}

	psCommand = fmt.Sprintf(`$FormatEnumerationLimit=-1;  Get-WmiObject -Query "%s" | Out-String -Width 4096`, SERVICE_TEST)
	stdOut, stdErr, exitCode, err = client.RunPSWithContext(context.Background(), psCommand)
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, stdOut, stdErr)
	if err != nil || (len(stdOut) == 0 && len(stdErr) > 0) {
		_ = exitCode
		fmt.Println(err)
	} else {
		fmt.Println("OK3")
	}

	stdOut, stdErr, exitCode, err = client.RunCmdWithContext(context.Background(), "sc query state= all")
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, stdOut, stdErr)
	if err != nil || (len(stdOut) == 0 && len(stdErr) > 0) {
		_ = exitCode
		fmt.Println(err)
	} else {
		fmt.Println("OK4")
	}

	psCommand = fmt.Sprintf(`$FormatEnumerationLimit=-1;  %s | Out-String -Width 4096`, COMMAND_RESOURCES_HYPERV_PS_CPU_MEMORY)
	stdOut, stdErr, exitCode, err = client.RunPSWithContext(context.Background(), psCommand)
	fmt.Printf("%d\n%v\n%s\n%s\n", exitCode, err, stdOut, stdErr)
	if err != nil || (len(stdOut) == 0 && len(stdErr) > 0) {
		_ = exitCode
		fmt.Println(err)
	} else {
		fmt.Println("OK5")
	}
}
