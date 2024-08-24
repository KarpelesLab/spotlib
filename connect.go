package spotlib

import (
	"context"

	"github.com/KarpelesLab/rest"
)

type hostResponse struct {
	Hosts []string `json:"hosts"`
}

func getHosts(ctx context.Context) ([]string, error) {
	// call Spot:connect API to fetch hosts we can connect to
	var res *hostResponse
	err := rest.Apply(ctx, "Spot:connect", "GET", nil, &res)
	if err != nil {
		return nil, err
	}
	return res.Hosts, nil
}
