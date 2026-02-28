// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = &HealthDataSource{}
var _ datasource.DataSourceWithConfigure = &HealthDataSource{}

// HealthDataSource reads the server health status.
type HealthDataSource struct {
	client *APIClient
}

type HealthDataSourceModel struct {
	Status     types.String `tfsdk:"status"`
	Version    types.String `tfsdk:"version"`
	UptimeSecs types.Int64  `tfsdk:"uptime_secs"`
}

func NewHealthDataSource() datasource.DataSource {
	return &HealthDataSource{}
}

func (d *HealthDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_health"
}

func (d *HealthDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads the Vellaveto server health status.",
		Attributes: map[string]schema.Attribute{
			"status": schema.StringAttribute{
				Description: "Server status (e.g., 'ok').",
				Computed:    true,
			},
			"version": schema.StringAttribute{
				Description: "Server version string.",
				Computed:    true,
			},
			"uptime_secs": schema.Int64Attribute{
				Description: "Server uptime in seconds.",
				Computed:    true,
			},
		},
	}
}

func (d *HealthDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected DataSource Configure Type",
			fmt.Sprintf("Expected *APIClient, got: %T", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *HealthDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, d.client.BaseURL+"/health", nil)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build request", err.Error())
		return
	}

	httpReq.Header.Set("Authorization", "Bearer "+d.client.APIKey)

	httpResp, err := d.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to check health", err.Error())
		return
	}
	defer httpResp.Body.Close()

	limited := io.LimitReader(httpResp.Body, 1*1024*1024)
	body, err := io.ReadAll(limited)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read response", err.Error())
		return
	}

	if httpResp.StatusCode != 200 {
		resp.Diagnostics.AddError(
			"API Error",
			fmt.Sprintf("Status %d: %s", httpResp.StatusCode, truncate(string(body), 256)),
		)
		return
	}

	var health map[string]interface{}
	if err := json.Unmarshal(body, &health); err != nil {
		resp.Diagnostics.AddError("Failed to parse response", err.Error())
		return
	}

	var model HealthDataSourceModel
	if status, ok := health["status"].(string); ok {
		model.Status = types.StringValue(status)
	}
	if version, ok := health["version"].(string); ok {
		model.Version = types.StringValue(version)
	}
	if uptime, ok := health["uptime_secs"].(float64); ok {
		model.UptimeSecs = types.Int64Value(int64(uptime))
	}

	diags := resp.State.Set(ctx, &model)
	resp.Diagnostics.Append(diags...)
}
