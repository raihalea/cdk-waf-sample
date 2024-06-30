# cdk-waf-sample-stack
AWS CDK WAF Configuration Sample

## Overview
This repository contains sample code for configuring AWS Web Application Firewall (WAF) using the AWS Cloud Development Kit (CDK).

## Configuration
You need to modify `waf-config.ts` and `waf.ts` to suit your specific environment.

### Files and Their Purposes
- [waf-config.ts](lib/waf-config.ts)
    - This file primarily includes settings used for IP filtering and geo-based rules.
- [waf.ts](lib/waf.ts)
    - This file contains specific rule configurations. It defines custom rules as well as integrates AWS Managed Rules.

Other components used in `waf.ts` can be found in `webacl.ts`, `statements.ts`, and `ipsets.ts`.

- [utils/waf/webacl.ts](/lib/utils/waf/webacl.ts)
    - Currently holds the region information for the WebACL.
- [utils/waf/statements.ts](/lib/utils/waf/statements.ts)
    - Handles the Statements that make up the WAF rules. Note that it does not fully cover all features available in WAFv2.
- [utils/waf/ipsets.ts](/lib/utils/waf/ipsets.ts)
    - Manages IP sets.