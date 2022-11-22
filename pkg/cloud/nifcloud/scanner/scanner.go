package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/trivy/pkg/cloud/nifcloud/cache"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/cloud/nifcloud"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type NIFCLOUDScanner struct {
}

func NewScanner() *NIFCLOUDScanner {
	return &NIFCLOUDScanner{}
}

func (s *NIFCLOUDScanner) Scan(ctx context.Context, option flag.Options) (scan.Results, bool, error) {

	nifcloudCache := cache.New(option.CacheDir, option.MaxCacheAge, option.Account, option.Region)
	included, missing := nifcloudCache.ListServices(option.Services)

	var scannerOpts []options.ScannerOption
	if !option.NoProgress {
		tracker := newProgressTracker()
		defer tracker.Finish()
		scannerOpts = append(scannerOpts, nifcloud.ScannerWithProgressTracker(tracker))
	}

	if len(missing) > 0 {
		scannerOpts = append(scannerOpts, nifcloud.ScannerWithNIFCLOUDServices(missing...))
	}

	if option.Debug {
		scannerOpts = append(scannerOpts, options.ScannerWithDebug(&defsecLogger{}))
	}

	if option.Trace {
		scannerOpts = append(scannerOpts, options.ScannerWithTrace(&defsecLogger{}))
	}

	if option.Region != "" {
		scannerOpts = append(
			scannerOpts,
			nifcloud.ScannerWithNIFCLOUDRegion(option.Region),
		)
	}

	if len(option.RegoOptions.PolicyPaths) > 0 {
		scannerOpts = append(
			scannerOpts,
			options.ScannerWithPolicyDirs(option.RegoOptions.PolicyPaths...),
		)
	}

	if len(option.RegoOptions.PolicyNamespaces) > 0 {
		scannerOpts = append(
			scannerOpts,
			options.ScannerWithPolicyNamespaces(option.RegoOptions.PolicyNamespaces...),
		)
	}

	scanner := nifcloud.New(scannerOpts...)

	var freshState *state.State
	if len(missing) > 0 {
		var err error
		freshState, err = scanner.CreateState(ctx)
		if err != nil {
			return nil, false, err
		}
	}

	var fullState *state.State
	if previousState, err := nifcloudCache.LoadState(); err == nil {
		if freshState != nil {
			fullState, err = previousState.Merge(freshState)
			if err != nil {
				return nil, false, err
			}
		} else {
			fullState = previousState
		}
	} else {
		fullState = freshState
	}

	if fullState == nil {
		return nil, false, fmt.Errorf("no resultant state found")
	}

	if err := nifcloudCache.AddServices(fullState, missing); err != nil {
		return nil, false, err
	}

	defsecResults, err := scanner.Scan(ctx, fullState)
	if err != nil {
		return nil, false, err
	}

	return defsecResults, len(included) > 0, nil
}

type defsecLogger struct {
}

func (d *defsecLogger) Write(p []byte) (n int, err error) {
	log.Logger.Debug("[defsec] " + strings.TrimSpace(string(p)))
	return len(p), nil
}
