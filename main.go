package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"https://github.com/LucianErick/trivy-plugin/pkg/common"
)

var (
	tempJsonFileName = "trivy-plugin-temp.json"
	version          = "dev"
)

func main() {
	if common.IsHelp() {
		helpMessage()
		return
	}

	pluginArgs, trivyCmd := common.RetrievePluginArguments([]string{"--plugin-output", "--output"})

	pluginOutput := pluginArgs["--plugin-output"]
	if pluginOutput == "" {
		log.Fatal("flag --plugin-output is required")
	}

	trivyOutputFileName := pluginArgs["--output"]
	if trivyOutputFileName == "" {
		trivyOutputFileName = filepath.Join(os.TempDir(), tempJsonFileName)
		defer removeFile(trivyOutputFileName)
	}

	if err := common.MakeTrivyJsonReport(trivyCmd, trivyOutputFileName); err != nil {
		log.Fatalf("failed to make trivy report: %v", err)
	}
	_, err := common.ReadReport(trivyOutputFileName)
	if err != nil {
		log.Fatalf("failed to get report from json: %v", err)
	}

	if err := saveResult(pluginOutput, []byte{}); err != nil {
		log.Fatalf("failed to save result: %v", err)
	}
}

func removeFile(file string) {
	if err := os.Remove(file); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}
}

func closeFile(file *os.File) {
	if err := file.Close(); err != nil {
		log.Fatalf("failed to remove file %v", err)
	}
}

func saveResult(filename string, result []byte) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = file.Write(result)
	if err != nil {
		return err
	}
	defer closeFile(file)
	return nil
}

func helpMessage() {
	_, err := fmt.Printf(`
		trivy-plugin v%s
		Usage: trivy trivy-plugin [-h,--help] command target filename
 		A Trivy common plugin.
		Options: -h, --help    Show usage.
		Examples:
			# example: trivy trivy-plugin
  			
`, version)
	if err != nil {
		log.Fatalf("Failed to display help message %v", err)
	}
	os.Exit(0)
}