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

var _ datasource.DataSource = &PoliciesDataSource{}
var _ datasource.DataSourceWithConfigure = &PoliciesDataSource{}

// PoliciesDataSource reads the list of loaded policies.
type PoliciesDataSource struct {
	client *APIClient
}

type PoliciesDataSourceModel struct {
	Policies []PolicyDataModel `tfsdk:"policies"`
}

type PolicyDataModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	PolicyType types.String `tfsdk:"policy_type"`
	Priority   types.Int64  `tfsdk:"priority"`
}

func NewPoliciesDataSource() datasource.DataSource {
	return &PoliciesDataSource{}
}

func (d *PoliciesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_policies"
}

func (d *PoliciesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists all loaded Vellaveto policies.",
		Attributes: map[string]schema.Attribute{
			"policies": schema.ListNestedAttribute{
				Description: "List of currently loaded policies.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "Policy unique identifier.",
							Computed:    true,
						},
						"name": schema.StringAttribute{
							Description: "Human-readable policy name.",
							Computed:    true,
						},
						"policy_type": schema.StringAttribute{
							Description: "Policy type.",
							Computed:    true,
						},
						"priority": schema.Int64Attribute{
							Description: "Policy evaluation priority.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *PoliciesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *PoliciesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, d.client.BaseURL+"/api/policies", nil)
	if err != nil {
		resp.Diagnostics.AddError("Failed to build request", err.Error())
		return
	}

	httpReq.Header.Set("Authorization", "Bearer "+d.client.APIKey)
	if d.client.TenantID != "" {
		httpReq.Header.Set("X-Tenant-ID", d.client.TenantID)
	}

	httpResp, err := d.client.HTTPClient.Do(httpReq)
	if err != nil {
		resp.Diagnostics.AddError("Failed to list policies", err.Error())
		return
	}
	defer httpResp.Body.Close()

	limited := io.LimitReader(httpResp.Body, 10*1024*1024)
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

	var rawPolicies []map[string]interface{}
	if err := json.Unmarshal(body, &rawPolicies); err != nil {
		resp.Diagnostics.AddError("Failed to parse response", err.Error())
		return
	}

	var model PoliciesDataSourceModel
	for _, rp := range rawPolicies {
		p := PolicyDataModel{}
		if id, ok := rp["id"].(string); ok {
			p.ID = types.StringValue(id)
		}
		if name, ok := rp["name"].(string); ok {
			p.Name = types.StringValue(name)
		}
		if pt, ok := rp["policy_type"].(string); ok {
			p.PolicyType = types.StringValue(pt)
		}
		if pri, ok := rp["priority"].(float64); ok {
			p.Priority = types.Int64Value(int64(pri))
		}
		model.Policies = append(model.Policies, p)
	}

	diags := resp.State.Set(ctx, &model)
	resp.Diagnostics.Append(diags...)
}
