package model

// Max list length = (budget - fixed) / per element, measured by spike S3 on
// OpenFGA v1.17.1, unchanged on v1.22.1 (worst case, no match). Re-measure on an OpenFGA upgrade.
const (
	inNetworkCostPerElement = 7
	inNetworkCostFixed      = 2

	inCostPerElement = 1
	inCostFixed      = 3

	containsCostPerElement = 1
	containsCostFixed      = 5
)
