package flag

var (
	nifcloudRegionFlag = Flag{
		Name:       "region",
		ConfigName: "cloud.nifcloud.region",
		Value:      "",
		Usage:      "NIFCLOUD Region to scan",
	}
	nifcloudServiceFlag = Flag{
		Name:       "service",
		ConfigName: "cloud.nifcloud.service",
		Value:      []string{},
		Usage:      "Only scan NIFCLOUD Service(s) specified with this flag. Can specify multiple services using --service A --service B etc.",
	}
	nifcloudAccountFlag = Flag{
		Name:       "account",
		ConfigName: "cloud.nifcloud.account",
		Value:      "",
		Usage:      "The NIFCLOUD account to scan. It's useful to specify this when reviewing cached results for multiple accounts.",
	}
)

type NIFCLOUDFlagGroup struct {
	Region   *Flag
	Services *Flag
	Account  *Flag
}

type NIFCLOUDOptions struct {
	Region   string
	Services []string
	Account  string
}

func NewNIFCLOUDFlagGroup() *NIFCLOUDFlagGroup {
	return &NIFCLOUDFlagGroup{
		Region:   &nifcloudRegionFlag,
		Services: &nifcloudServiceFlag,
		Account:  &nifcloudAccountFlag,
	}
}

func (f *NIFCLOUDFlagGroup) Name() string {
	return "NIFCLOUD"
}

func (f *NIFCLOUDFlagGroup) Flags() []*Flag {
	return []*Flag{f.Region, f.Services}
}

func (f *NIFCLOUDFlagGroup) ToOptions() NIFCLOUDOptions {
	return NIFCLOUDOptions{
		Region:   getString(f.Region),
		Services: getStringSlice(f.Services),
		Account:  getString(f.Account),
	}
}
