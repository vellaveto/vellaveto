import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.3/index.js';

// Custom metrics
const evaluationLatency = new Trend('evaluation_latency_ms');
const denyRate = new Rate('deny_rate');
const errorRate = new Rate('error_rate');

// Test configuration
export const options = {
    scenarios: {
        // Ramp-up test: gradually increase to 500 concurrent users
        ramp_up: {
            executor: 'ramping-vus',
            startVUs: 1,
            stages: [
                { duration: '30s', target: 50 },
                { duration: '1m', target: 200 },
                { duration: '2m', target: 500 },
                { duration: '1m', target: 500 },  // hold at peak
                { duration: '30s', target: 0 },
            ],
        },
        // Sustained throughput test: constant 1000 req/s for 5 minutes
        sustained: {
            executor: 'constant-arrival-rate',
            rate: 1000,
            timeUnit: '1s',
            duration: '5m',
            preAllocatedVUs: 100,
            maxVUs: 500,
            startTime: '6m',  // start after ramp_up
        },
        // Spike test: sudden burst to 2000 req/s
        spike: {
            executor: 'ramping-arrival-rate',
            startRate: 100,
            timeUnit: '1s',
            stages: [
                { duration: '10s', target: 100 },
                { duration: '5s', target: 2000 },
                { duration: '30s', target: 2000 },
                { duration: '10s', target: 100 },
            ],
            preAllocatedVUs: 200,
            maxVUs: 1000,
            startTime: '12m',
        },
    },
    thresholds: {
        http_req_duration: ['p(99)<5'],  // P99 < 5ms
        http_req_failed: ['rate<0.01'],   // < 1% error rate
        evaluation_latency_ms: ['p(99)<5'],
    },
};

const BASE_URL = __ENV.VELLAVETO_URL || 'http://localhost:3000';

// Generate diverse actions for realistic load
const tools = ['filesystem', 'http_client', 'database', 'shell', 'browser', 'email'];
const functions = ['read', 'write', 'delete', 'list', 'execute', 'query'];

function randomAction() {
    const tool = tools[Math.floor(Math.random() * tools.length)];
    const func = functions[Math.floor(Math.random() * functions.length)];
    return {
        tool: tool,
        function: func,
        parameters: {
            path: `/workspace/project/file_${Math.floor(Math.random() * 1000)}.txt`,
        },
        target_paths: [`/workspace/project/file_${Math.floor(Math.random() * 1000)}.txt`],
        target_domains: [],
    };
}

export default function () {
    const payload = JSON.stringify(randomAction());
    const params = {
        headers: {
            'Content-Type': 'application/json',
        },
        tags: { name: 'evaluate' },
    };

    const start = Date.now();
    const res = http.post(`${BASE_URL}/api/evaluate`, payload, params);
    const elapsed = Date.now() - start;

    evaluationLatency.add(elapsed);
    errorRate.add(res.status >= 500);

    check(res, {
        'status is 200': (r) => r.status === 200,
        'has verdict': (r) => {
            try {
                const body = JSON.parse(r.body);
                return body.verdict !== undefined;
            } catch {
                return false;
            }
        },
        'latency under 5ms': () => elapsed < 5,
    });

    if (res.status === 200) {
        try {
            const body = JSON.parse(res.body);
            denyRate.add(body.verdict === 'Deny' || (body.verdict && body.verdict.Deny));
        } catch {
            // ignore parse errors
        }
    }
}

export function handleSummary(data) {
    const summary = {
        timestamp: new Date().toISOString(),
        scenarios: Object.keys(options.scenarios),
        metrics: {
            total_requests: data.metrics.http_reqs ? data.metrics.http_reqs.values.count : 0,
            avg_latency_ms: data.metrics.http_req_duration ? data.metrics.http_req_duration.values.avg : 0,
            p95_latency_ms: data.metrics.http_req_duration ? data.metrics.http_req_duration.values['p(95)'] : 0,
            p99_latency_ms: data.metrics.http_req_duration ? data.metrics.http_req_duration.values['p(99)'] : 0,
            max_latency_ms: data.metrics.http_req_duration ? data.metrics.http_req_duration.values.max : 0,
            error_rate: data.metrics.http_req_failed ? data.metrics.http_req_failed.values.rate : 0,
            rps: data.metrics.http_reqs ? data.metrics.http_reqs.values.rate : 0,
        },
        thresholds: data.thresholds || {},
    };

    return {
        'perf/results/latest.json': JSON.stringify(summary, null, 2),
        stdout: textSummary(data, { indent: '  ', enableColors: true }),
    };
}
