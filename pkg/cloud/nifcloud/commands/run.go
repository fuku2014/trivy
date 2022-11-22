package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/pkg/errs"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"

	"github.com/aquasecurity/trivy/pkg/cloud"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/aquasecurity/trivy/pkg/cloud/nifcloud/scanner"
	"github.com/aquasecurity/trivy/pkg/cloud/report"

	"github.com/aquasecurity/trivy/pkg/log"

	nifcloudScanner "github.com/aquasecurity/defsec/pkg/scanners/cloud/nifcloud"
)

func processOptions(ctx context.Context, opt *flag.Options) error {
	// support comma separated services too
	var splitServices []string
	for _, service := range opt.Services {
		splitServices = append(splitServices, strings.Split(service, ",")...)
	}
	opt.Services = splitServices

	if len(opt.Services) == 0 {
		log.Logger.Debug("No service(s) specified, scanning all services...")
		opt.Services = nifcloudScanner.AllSupportedServices()
	} else {
		log.Logger.Debugf("Specific services were requested: [%s]...", strings.Join(opt.Services, ", "))
		for _, service := range opt.Services {
			var found bool
			supported := nifcloudScanner.AllSupportedServices()
			for _, allowed := range supported {
				if allowed == service {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("service '%s' is not currently supported - supported services are: %s", service, strings.Join(supported, ", "))
			}
		}
	}

	return nil
}

func Run(ctx context.Context, opt flag.Options) error {

	ctx, cancel := context.WithTimeout(ctx, opt.GlobalOptions.Timeout)
	defer cancel()

	if err := log.InitLogger(opt.Debug, false); err != nil {
		return fmt.Errorf("logger error: %w", err)
	}

	var err error
	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	if err := processOptions(ctx, &opt); err != nil {
		return err
	}

	results, cached, err := scanner.NewScanner().Scan(ctx, opt)
	if err != nil {
		var aerr errs.AdapterError
		if errors.As(err, &aerr) {
			for _, e := range aerr.Errors() {
				log.Logger.Warnf("Adapter error: %s", e)
			}
		} else {
			return fmt.Errorf("nifcloud scan error: %w", err)
		}
	}
	r := report.New(cloud.ProviderNIFCLOUD, opt.Account, opt.Region, results.GetFailed(), opt.Services)

	log.Logger.Debug("Writing report to output...")
	if err := report.Write(r, opt, cached); err != nil {
		return fmt.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, r.Failed())
	return nil
}
