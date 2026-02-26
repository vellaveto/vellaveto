import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const crossTenantLeaks = new Counter('cross_tenant_leaks');

export const options = {
    scenarios: {
        tenant_a: {
            executor: 'constant-vus',
            vus: 50,
            duration: '2m',
            env: { TENANT: 'tenant-alpha' },
            tags: { tenant: 'alpha' },
        },
        tenant_b: {
            executor: 'constant-vus',
            vus: 50,
            duration: '2m',
            env: { TENANT: 'tenant-beta' },
            tags: { tenant: 'beta' },
        },
        tenant_c: {
            executor: 'constant-vus',
            vus: 50,
            duration: '2m',
            env: { TENANT: 'tenant-gamma' },
            tags: { tenant: 'gamma' },
        },
    },
    thresholds: {
        cross_tenant_leaks: ['count==0'],  // Zero cross-tenant leakage
        http_req_duration: ['p(99)<10'],
    },
};

const BASE_URL = __ENV.VELLAVETO_URL || 'http://localhost:3000';

export default function () {
    const tenant = __ENV.TENANT;
    const payload = JSON.stringify({
        tool: `${tenant}_tool`,
        function: 'read',
        parameters: { tenant_id: tenant },
        target_paths: [],
        target_domains: [],
    });

    const params = {
        headers: {
            'Content-Type': 'application/json',
            'X-Tenant-ID': tenant,
        },
    };

    const res = http.post(`${BASE_URL}/api/evaluate`, payload, params);

    if (res.status === 200) {
        try {
            const body = JSON.parse(res.body);
            // Check that response doesn't contain other tenants' data
            const bodyStr = JSON.stringify(body);
            const otherTenants = ['tenant-alpha', 'tenant-beta', 'tenant-gamma'].filter(t => t !== tenant);
            for (const other of otherTenants) {
                if (bodyStr.includes(other)) {
                    crossTenantLeaks.add(1);
                }
            }
        } catch {
            // ignore
        }
    }

    check(res, {
        'status is 200': (r) => r.status === 200,
    });
}
