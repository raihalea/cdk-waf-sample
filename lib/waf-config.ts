interface WafConfig {
  limitRateRequestsRule: limitRateRequestsRuleConfig;
  adminIpsRule: RuleEnableWithIpConfig;
  blockNonSpecificIpsRule: RuleEnableWithIpConfig;
  geoMatchRule: GeoMatchRuleConfig;
}
interface limitRateRequestsRuleConfig {
  rateByIp?: number
}
interface RuleEnableWithIpConfig {
  IPv4List?: string[];
  IPv6List?: string[];
}
interface RuleEnableWithIpConfig {
  IPv4List?: string[];
  IPv6List?: string[];
}
interface GeoMatchRuleConfig {
  allowCountries?: string[]
}

export const wafConfig: WafConfig = {
  adminIpsRule: {
    IPv4List: [
      "192.0.2.0/24",
      // "198.51.100.0/24"
    ],
    // IPv6List: [
    //   "2001:db8::/32",
    // ],
  },
  blockNonSpecificIpsRule: {
    IPv4List: [
      // "192.0.2.0/24",
      // "198.51.100.0/24"
    ],
    IPv6List: [
      "2001:db8::/32",
    ],
  },
  geoMatchRule: {
    allowCountries: ["JP", "US"],
  },
  limitRateRequestsRule: {
    rateByIp: 1000,
  },
};
