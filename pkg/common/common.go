package common

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	k8sReport "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"

	"golang.org/x/exp/slices"
)

var ErrorJsonUnknownField = errors.New("json: unknown field")

// IsHelp checks if the "--help" or "-h" flag is present in the command-line arguments.
func IsHelp() bool {
	return slices.Contains(os.Args, "--help") || slices.Contains(os.Args, "-h")
}

// ReadReport reads and parses a report from the specified file.
func ReadReport(fileName string) (*types.Report, error) {

	log.Println("Read report", fileName)

	report, err := readAndParseJson[types.Report](fileName)
	if err == nil {
		return report, nil
	}

	if err != ErrorJsonUnknownField {
		return nil, fmt.Errorf("failed to read report %v", err)
	}

	k8s, err := readAndParseJson[k8sReport.Report](fileName)
	if err == nil {
		return convertK8sReportToReport(k8s), nil
	}

	return nil, fmt.Errorf("failed to read report %v", err)
}

// readAndParseJson reads and parses JSON data from a file.
func readAndParseJson[T any](fileName string) (*T, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := f.Close()
		if err != nil {
			log.Println("failed to close file", err)
		}
	}()

	return parseJsonStrict[T](f)
}

// parseJsonStrict parses JSON data strictly, disallowing unknown fields.
func parseJsonStrict[T any](r io.Reader) (*T, error) {
	var out T

	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&out); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			return nil, ErrorJsonUnknownField
		}
		return nil, err
	}

	return &out, nil
}

// convertK8sReportToReport converts a Kubernetes report to a standard report.
func convertK8sReportToReport(k8s *k8sReport.Report) *types.Report {
	var results types.Results
	for _, vuln := range k8s.Vulnerabilities {
		results = append(results, vuln.Results...)
	}
	for _, misc := range k8s.Misconfigurations {
		results = append(results, misc.Results...)
	}

	return &types.Report{
		Results: results,
	}
}

// GetPathToPluginDir returns the path to a plugin directory based on the executable's location.
func GetPathToPluginDir(fileName string) (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(ex), fileName), nil
}

// GetPathToTemplate returns the path to a template file in the plugin directory.
func GetPathToTemplate(fileName string) (string, error) {
	path, err := GetPathToPluginDir(fileName)
	if err != nil {
		return "", err
	}
	return "@" + path, nil
}

// ReadPluginFile reads a file from the plugin directory.
func ReadPluginFile(fileName string) ([]byte, error) {
	path, err := GetPathToPluginDir(fileName)
	if err != nil {
		return nil, err
	}

	return os.ReadFile(path)
}

// MakeTrivyJsonReport generates a JSON report using the Trivy command.
func MakeTrivyJsonReport(trivyCommand []string, outputFileName string) error {
	cmdArgs := append(trivyCommand, "--format", "json", "--output", outputFileName)
	cmd := exec.Command("trivy", cmdArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run trivy: %w", err)
	}
	return nil
}

// Arguments represents a map of plugin arguments.
type Arguments map[string]string

// RetrievePluginArguments retrieves plugin arguments from the command-line.
func RetrievePluginArguments(availableArguments []string) (pluginArgs Arguments, rest []string) {
	trivyCommand := make([]string, 0, len(os.Args))
	args := make(map[string]string)
	for i := 0; i < len(os.Args); i++ {
		if slices.Contains(availableArguments, os.Args[i]) {
			if i+1 >= len(os.Args) {
				args[os.Args[i]] = ""
			} else {
				args[os.Args[i]] = os.Args[i+1]
			}
			i++ // skip argument value
		} else {
			trivyCommand = append(trivyCommand, os.Args[i])
		}
	}
	return args, trivyCommand[1:]
}