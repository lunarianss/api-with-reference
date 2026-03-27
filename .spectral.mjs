// OWASP API Security Top 10 (2023) - Spectral Ruleset
// ESM format for use with Spectral v6+
// Usage: spectral lint openapi.yaml --ruleset owasp-top10.spectral.mjs

import { truthy, falsy, defined, pattern, schema } from "@stoplight/spectral-functions";
import { oas } from "@stoplight/spectral-rulesets";

export default {
  extends: [oas],
  rules: {
    // ========================================================================
    // OWASP API1:2023 - Broken Object Level Authorization (BOLA)
    // https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
    // ========================================================================

    "owasp:api1:2023-broken-object-level-authorization": {
      description:
        "OWASP API1:2023 - Check that all path parameters have associated security schemes to prevent Broken Object Level Authorization (BOLA).",
      message:
        "{{description}}. Path '{{path}}' should define security schemes to protect object-level access.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
      severity: "error",
      given: "$.paths[*][get,put,patch,delete]",
      then: {
        field: "security",
        function: truthy,
      },
    },

    "owasp:api1:2023-no-unevaluated-properties": {
      description:
        "OWASP API1:2023 - Schemas should restrict unevaluated properties to prevent mass assignment leading to BOLA.",
      message:
        "{{description}}. Schema '{{path}}' should set additionalProperties to false.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
      severity: "warn",
      given: "$..[?(@ && @.type === 'object')]",
      then: {
        field: "additionalProperties",
        function: defined,
      },
    },

    // ========================================================================
    // OWASP API2:2023 - Broken Authentication
    // https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
    // ========================================================================

    "owasp:api2:2023-broken-authentication-no-empty-security": {
      description:
        "OWASP API2:2023 - Security schemes must not be empty to prevent Broken Authentication.",
      message:
        "{{description}}. Operation '{{path}}' has an empty security array, allowing unauthenticated access.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
      severity: "error",
      given: "$.paths[*][get,post,put,patch,delete].security[*]",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            type: "object",
            minProperties: 1,
          },
        },
      },
    },

    "owasp:api2:2023-broken-authentication-jwt-best-practices": {
      description:
        "OWASP API2:2023 - Security scheme using JWT should use a URL to restrict the algorithm (e.g. RS256).",
      message:
        "{{description}}. Security scheme '{{path}}' should define bearerFormat as 'JWT' for bearer tokens.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
      severity: "info",
      given:
        "$.components.securitySchemes[?(@ && @.type === 'http' && @.scheme === 'bearer')]",
      then: {
        field: "bearerFormat",
        function: truthy,
      },
    },

    "owasp:api2:2023-broken-authentication-global-security": {
      description:
        "OWASP API2:2023 - Global security field should be defined to enforce authentication by default.",
      message:
        "{{description}}. The OpenAPI document does not have a global 'security' field.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
      severity: "error",
      given: "$",
      then: {
        field: "security",
        function: truthy,
      },
    },

    // ========================================================================
    // OWASP API3:2023 - Broken Object Property Level Authorization
    // https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
    // ========================================================================

    "owasp:api3:2023-broken-object-property-level-authorization": {
      description:
        "OWASP API3:2023 - Response schemas should define properties explicitly to prevent excessive data exposure.",
      message:
        "{{description}}. Schema at '{{path}}' should define its properties explicitly.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
      severity: "warn",
      given: "$.paths[*][*].responses[*].content[*].schema",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            oneOf: [
              { required: ["properties"] },
              { required: ["$ref"] },
              { required: ["allOf"] },
              { required: ["oneOf"] },
              { required: ["anyOf"] },
              { required: ["items"] },
            ],
          },
        },
      },
    },

    "owasp:api3:2023-no-additionalProperties-in-response": {
      description:
        "OWASP API3:2023 - Response object schemas should not allow additional properties to prevent data leakage.",
      message:
        "{{description}}. Response schema '{{path}}' should set 'additionalProperties: false'.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
      severity: "warn",
      given:
        "$.paths[*][*].responses[*].content[*].schema[?(@ && @.type === 'object')]",
      then: {
        field: "additionalProperties",
        function: falsy,
      },
    },

    // ========================================================================
    // OWASP API4:2023 - Unrestricted Resource Consumption
    // https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
    // ========================================================================

    "owasp:api4:2023-unrestricted-resource-consumption-rate-limit": {
      description:
        "OWASP API4:2023 - Responses should include rate limiting headers to prevent unrestricted resource consumption.",
      message:
        "{{description}}. Response '{{path}}' should contain rate limiting headers (X-RateLimit-Limit, RateLimit).",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
      severity: "warn",
      given: "$.paths[*][*].responses['200','201','204']",
      then: {
        field: "headers",
        function: truthy,
      },
    },

    "owasp:api4:2023-unrestricted-resource-consumption-array-limit": {
      description:
        "OWASP API4:2023 - Array schemas should define maxItems to prevent memory exhaustion attacks.",
      message:
        "{{description}}. Array schema at '{{path}}' should define 'maxItems'.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
      severity: "warn",
      given: "$..[?(@ && @.type === 'array')]",
      then: {
        field: "maxItems",
        function: defined,
      },
    },

    "owasp:api4:2023-unrestricted-resource-consumption-string-limit": {
      description:
        "OWASP API4:2023 - String schemas should define maxLength to prevent abuse.",
      message:
        "{{description}}. String schema at '{{path}}' should define 'maxLength'.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
      severity: "warn",
      given: "$..[?(@ && @.type === 'string')]",
      then: {
        field: "maxLength",
        function: defined,
      },
    },

    "owasp:api4:2023-unrestricted-resource-consumption-integer-limit": {
      description:
        "OWASP API4:2023 - Integer schemas should define maximum to prevent unreasonable values.",
      message:
        "{{description}}. Integer schema at '{{path}}' should define 'maximum'.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
      severity: "warn",
      given: "$..[?(@ && @.type === 'integer')]",
      then: {
        field: "maximum",
        function: defined,
      },
    },

    "owasp:api4:2023-unrestricted-resource-consumption-pagination": {
      description:
        "OWASP API4:2023 - GET endpoints returning lists should support pagination parameters.",
      message:
        "{{description}}. GET operation at '{{path}}' that returns an array should support pagination.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
      severity: "info",
      given: "$.paths[*].get",
      then: {
        field: "parameters",
        function: truthy,
      },
    },

    // ========================================================================
    // OWASP API5:2023 - Broken Function Level Authorization
    // https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
    // ========================================================================

    "owasp:api5:2023-broken-function-level-authorization-admin-security": {
      description:
        "OWASP API5:2023 - Admin endpoints should have stricter security to prevent Broken Function Level Authorization.",
      message:
        "{{description}}. Admin-related path '{{path}}' must define security schemes.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
      severity: "error",
      given:
        "$.paths[?(@property.match(/admin|manage|internal|superuser/i))][get,post,put,patch,delete]",
      then: {
        field: "security",
        function: truthy,
      },
    },

    "owasp:api5:2023-broken-function-level-authorization-method-restriction": {
      description:
        "OWASP API5:2023 - Sensitive operations (POST, PUT, DELETE, PATCH) should require authentication.",
      message:
        "{{description}}. Write operation at '{{path}}' must define security.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
      severity: "error",
      given: "$.paths[*][post,put,delete,patch]",
      then: {
        field: "security",
        function: truthy,
      },
    },

    // ========================================================================
    // OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows
    // https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
    // ========================================================================

    "owasp:api6:2023-unrestricted-access-to-sensitive-business-flows": {
      description:
        "OWASP API6:2023 - Sensitive business flows should have rate limiting and security mechanisms.",
      message:
        "{{description}}. Sensitive operation at '{{path}}' should include rate limit response (429).",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
      severity: "warn",
      given: "$.paths[*][post,put].responses",
      then: {
        field: "429",
        function: truthy,
      },
    },

    // ========================================================================
    // OWASP API7:2023 - Server Side Request Forgery (SSRF)
    // https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
    // ========================================================================

    "owasp:api7:2023-server-side-request-forgery-no-http-urls": {
      description:
        "OWASP API7:2023 - Server URLs should use HTTPS to prevent SSRF and MITM attacks.",
      message:
        "{{description}}. Server URL '{{value}}' should use HTTPS instead of HTTP.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
      severity: "error",
      given: "$.servers[*].url",
      then: {
        function: pattern,
        functionOptions: {
          match: "^https://",
        },
      },
    },

    "owasp:api7:2023-server-side-request-forgery-url-validation": {
      description:
        "OWASP API7:2023 - URL parameters accepting user input should define format to prevent SSRF.",
      message:
        "{{description}}. URL parameter at '{{path}}' should define 'format: uri' with pattern validation.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
      severity: "warn",
      given:
        "$.paths[*][*]..parameters[?(@ && @.schema && @.schema.format === 'uri')]",
      then: [
        {
          field: "schema.pattern",
          function: truthy,
        },
      ],
    },

    // ========================================================================
    // OWASP API8:2023 - Security Misconfiguration
    // https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
    // ========================================================================

    "owasp:api8:2023-security-misconfiguration-cors": {
      description:
        "OWASP API8:2023 - Servers should not use wildcard URLs that may indicate CORS misconfiguration.",
      message:
        "{{description}}. Server URL at '{{path}}' should not use wildcards.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
      severity: "error",
      given: "$.servers[*].url",
      then: {
        function: pattern,
        functionOptions: {
          notMatch: "\\*",
        },
      },
    },

    "owasp:api8:2023-security-misconfiguration-error-response": {
      description:
        "OWASP API8:2023 - Error responses (4xx, 5xx) should be defined to avoid exposing stack traces or internal details.",
      message:
        "{{description}}. Operation at '{{path}}' should define error responses (4xx/5xx).",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
      severity: "warn",
      given: "$.paths[*][get,post,put,patch,delete].responses",
      then: {
        function: schema,
        functionOptions: {
          schema: {
            anyOf: [
              { required: ["400"] },
              { required: ["401"] },
              { required: ["403"] },
              { required: ["404"] },
              { required: ["500"] },
              { required: ["default"] },
            ],
          },
        },
      },
    },

    "owasp:api8:2023-security-misconfiguration-define-security-schemes": {
      description:
        "OWASP API8:2023 - The API should define security schemes in components.",
      message:
        "{{description}}. The document should have 'components.securitySchemes' defined.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
      severity: "error",
      given: "$.components",
      then: {
        field: "securitySchemes",
        function: truthy,
      },
    },

    // ========================================================================
    // OWASP API9:2023 - Improper Inventory Management
    // https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/
    // ========================================================================

    "owasp:api9:2023-improper-inventory-management-description": {
      description:
        "OWASP API9:2023 - All operations should have descriptions for proper inventory management.",
      message:
        "{{description}}. Operation at '{{path}}' should have a description.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
      severity: "warn",
      given: "$.paths[*][get,post,put,patch,delete]",
      then: {
        field: "description",
        function: truthy,
      },
    },

    "owasp:api9:2023-improper-inventory-management-servers": {
      description:
        "OWASP API9:2023 - API should define servers to allow proper inventory management and avoid exposing debug/staging endpoints.",
      message:
        "{{description}}. The document should define at least one server.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
      severity: "warn",
      given: "$",
      then: {
        field: "servers",
        function: truthy,
      },
    },

    "owasp:api9:2023-improper-inventory-management-no-api-versioning": {
      description:
        "OWASP API9:2023 - Server URLs should include API versioning for proper lifecycle management.",
      message:
        "{{description}}. Server URL '{{value}}' should include a version identifier (e.g., /v1/).",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
      severity: "info",
      given: "$.servers[*].url",
      then: {
        function: pattern,
        functionOptions: {
          match: "/v[0-9]+[./]?",
        },
      },
    },

    "owasp:api9:2023-improper-inventory-management-api-info": {
      description:
        "OWASP API9:2023 - API should document info with contact, license and terms of service for proper governance.",
      message:
        "{{description}}. The 'info' object at '{{path}}' should include contact information.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
      severity: "info",
      given: "$.info",
      then: [
        {
          field: "contact",
          function: truthy,
        },
      ],
    },

    // ========================================================================
    // OWASP API10:2023 - Unsafe Consumption of APIs
    // https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
    // ========================================================================

    "owasp:api10:2023-unsafe-consumption-of-apis-server-description": {
      description:
        "OWASP API10:2023 - Server entries should have descriptions to document the purpose and trust level of external APIs.",
      message:
        "{{description}}. Server at '{{path}}' should have a 'description'.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
      severity: "info",
      given: "$.servers[*]",
      then: {
        field: "description",
        function: truthy,
      },
    },

    "owasp:api10:2023-unsafe-consumption-of-apis-external-link-description": {
      description:
        "OWASP API10:2023 - External documentation links should have descriptions to identify trusted vs untrusted sources.",
      message:
        "{{description}}. External docs at '{{path}}' should have a description.",
      documentationUrl:
        "https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/",
      severity: "info",
      given: "$.externalDocs",
      then: {
        field: "description",
        function: truthy,
      },
    },
  },
};
