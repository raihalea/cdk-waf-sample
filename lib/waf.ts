import { RemovalPolicy, Stack, Names } from "aws-cdk-lib";
// import { Duration, RemovalPolicy, Stack, Names } from 'aws-cdk-lib';
// import { Bucket } from "aws-cdk-lib/aws-s3";
import { LogGroup, RetentionDays } from "aws-cdk-lib/aws-logs";
// import { LogGroup, RetentionDays, CfnLogGroup } from 'aws-cdk-lib/aws-logs';
import {
  CfnRuleGroup,
  CfnWebACL,
  CfnIPSet,
  CfnLoggingConfiguration,
  CfnWebACLAssociation,
} from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";
import { WafIpSets } from "./utils/waf/ipsets";
import { WafStatements } from "./utils/waf/statements";
import { wafConfig } from "./waf-config";
import { WebAclScope } from "./utils/waf/webacl";

/**
 * Represents a dictionary of WAF IP sets used for different rules.
 */
export interface WafIpSetsDict {
  adminIpsSetList: WafIpSets;
  blockNonSpecificIpsRule: WafIpSets;
}

/**
 * Defines a WAF configuration.
 * This class creates WAF rules and a Web ACL based on provided configurations.
 */
export class Waf extends Construct {
  /**
   * See: https://github.com/aws-samples/aws-cdk-examples/blob/master/typescript/waf/waf-cloudfront.ts
   */

  readonly webAclId?: string;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    const stack = Stack.of(this);
    const stackId = Names.uniqueResourceName(this, {}).toLowerCase();
    const region = stack.region;
    const logName = `aws-waf-logs-${stackId}-${region}`;

    // const wafBucket = new Bucket(this, "S3", {
    //   bucketName: logName,
    //   enforceSSL: true,
    //   autoDeleteObjects: true,
    //   removalPolicy: RemovalPolicy.DESTROY,
    //   lifecycleRules: [
    //     {
    //       expiration: Duration.days(7),
    //     },
    //   ],
    // });

    const webAclScope = WebAclScope.CLOUDFRONT;

    const logGroup = new LogGroup(this, "WafLogGroup", {
      logGroupName: logName,
      retention: RetentionDays.ONE_WEEK,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    const ipSetsDict = {
      adminIpsSetList: new WafIpSets(this, "adminIpsSetList", {
        namePrefix: "Admin",
        ipv4List: wafConfig.adminIpsRule.IPv4List,
        ipv6List: wafConfig.adminIpsRule.IPv6List,
        webAclScope: webAclScope,
      }),
      blockNonSpecificIpsRule: new WafIpSets(this, "BlockNonSpecificIpsRule", {
        namePrefix: "BlockNonSpecificIpsRule",
        ipv4List: wafConfig.blockNonSpecificIpsRule.IPv4List,
        ipv6List: wafConfig.blockNonSpecificIpsRule.IPv6List,
        webAclScope: webAclScope,
      }),
    };

    const wafAcl = new CfnWebACL(this, "WafCloudFront", {
      defaultAction: { allow: {} },
      scope: webAclScope,
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "waf-cloudfront",
        sampledRequestsEnabled: true,
      },
      rules: this.makeRules(ipSetsDict),
    });

    new CfnLoggingConfiguration(this, "WafLogging", {
      resourceArn: wafAcl.attrArn,
      logDestinationConfigs: [logGroup.logGroupArn],
    });

    this.webAclId = wafAcl.attrArn;
  }

  /**
   * Generates an array of rule properties for the WAF ACL based on the configuration.
   * @param ipSetsDict Dictionary containing IP sets for rule creation.
   * @returns An array of CfnRuleGroup.RuleProperty for inclusion in a WebACL.
   */
  private makeRules(ipSetsDict: WafIpSetsDict): CfnRuleGroup.RuleProperty[] {
    const rules: CfnRuleGroup.RuleProperty[] = [];

    // Rate Based Rule
    const limitRateRequestsRule = this.createRuleLimitRequests(
      rules.length,
      wafConfig.limitRateRequestsRule.rateByIp
    );
    if (limitRateRequestsRule) {
      rules.push(limitRateRequestsRule);
    }

    // allows requests from specific IPs
    const adminIpRule = this.createSizeRestrictionExcludedAdminIps(
      rules.length,
      ipSetsDict.adminIpsSetList.ipSetList
    );
    rules.push(adminIpRule);

    // IP Block Rule
    const blockUnlistedIps = this.createRuleBlockUnlistedIps(
      rules.length,
      ipSetsDict.blockNonSpecificIpsRule.ipSetList
    );
    if (blockUnlistedIps) {
      rules.push(blockUnlistedIps);
    }

    // Geo Based Rule
    const geoMatchRule = this.createRuleBlockOutsideAllowedCountries(
      rules.length,
      wafConfig.geoMatchRule.allowCountries
    );
    if (geoMatchRule) {
      rules.push(geoMatchRule);
    }

    // AWS ManagedRules
    const managedRuleGroups = this.createManagedRules(rules.length);
    rules.push(...managedRuleGroups);

    // my rule
    const XsslabelMatchRule = this.createRuleXSSLabelMatch(
      rules.length,
      ipSetsDict.adminIpsSetList.ipSetList
    );
    rules.push(XsslabelMatchRule);

    return rules;
  }

  private createSizeRestrictionExcludedAdminIps(
    priority: number,
    adminIpsSetList: CfnIPSet[]
  ): CfnRuleGroup.RuleProperty {
    const urlConditons = WafStatements.or(
      WafStatements.startsWithURL("/api/"),
      WafStatements.exactlyURL("/setup")
    );

    let combinedConditions;
    if (adminIpsSetList.length === 0) {
      combinedConditions = urlConditons;
    } else {
      combinedConditions = WafStatements.and(
        urlConditons,
        WafStatements.ipv4v6Match(adminIpsSetList)
      );
    }

    return WafStatements.block(
      "SizeRestriction",
      priority,
      WafStatements.and(
        WafStatements.oversizedRequestBody(16 * 1024), //16KB
        WafStatements.not(combinedConditions)
      )
    );
  }

  private createRuleLimitRequests(
    priority: number,
    rateByIp?: number
  ): CfnRuleGroup.RuleProperty | undefined {
    if (!rateByIp) {
      return undefined;
    } else {
      return WafStatements.block(
        "RateLimitRequests",
        priority,
        WafStatements.rateBasedByIp(rateByIp)
      );
    }
  }

  private createRuleBlockUnlistedIps(
    priority: number,
    blockUnlistedIpsSetList: CfnIPSet[]
  ): CfnRuleGroup.RuleProperty | undefined {
    const ipSetList = blockUnlistedIpsSetList;

    if (ipSetList.length === 0) {
      return undefined;
    } else {
      return WafStatements.block(
        "BlockUnlistedIps",
        priority,
        WafStatements.not(WafStatements.ipv4v6Match(ipSetList))
      );
    }
  }

  private createRuleBlockOutsideAllowedCountries(
    priority: number,
    countryCodes?: string[]
  ): CfnRuleGroup.RuleProperty | undefined {
    if (!countryCodes) {
      return undefined;
    } else {
      return WafStatements.block(
        "BlockOutsideAllowedCountries",
        priority,
        WafStatements.not(WafStatements.matchCountryCodes(countryCodes))
      );
    }
  }

  private createRuleXSSLabelMatch(
    priority: number,
    adminIpsSetList: CfnIPSet[]
  ): CfnRuleGroup.RuleProperty {
    const ipSetList = adminIpsSetList;

    const urlConditons = WafStatements.or(
      WafStatements.startsWithURL("/api/"),
      WafStatements.exactlyURL("/setup")
    );

    let combinedConditions;
    if (ipSetList.length === 0) {
      combinedConditions = urlConditons;
    } else {
      combinedConditions = WafStatements.and(
        urlConditons,
        WafStatements.ipv4v6Match(ipSetList)
      );
    }

    return WafStatements.block(
      "XssLabelMatch",
      priority,
      WafStatements.and(
        WafStatements.matchLabel(
          "LABEL",
          "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
        ),
        WafStatements.not(combinedConditions)
      )
    );
  }

  // aws managed rules
  private createManagedRules(
    startPriorityNumber: number
  ): CfnRuleGroup.RuleProperty[] {
    var rules: CfnRuleGroup.RuleProperty[] = [];
    interface listOfRules {
      name: string;
      priority?: number;
      overrideAction: string;
      excludedRules: string[];
      scopeDownStatement?: CfnWebACL.StatementProperty;
    }
    const managedRules: listOfRules[] = [
      // {
      //   name: "EXAMPLE_MANAGED_RULEGROUP",
      //   priority: 20, // if not specified, priority is automatically assigned.
      //   overrideAction: "none",
      //   excludedRules: ["EXCLUDED_MANAGED_RULE"],
      //   scopeDownStatement: WafStatements.not(WafStatements.startsWithURL("/admin")),
      // },
      {
        name: "AWSManagedRulesCommonRuleSet",
        overrideAction: "none",
        excludedRules: ["SizeRestrictions_BODY", "CrossSiteScripting_BODY"],
      },
      {
        name: "AWSManagedRulesAmazonIpReputationList",
        overrideAction: "none",
        excludedRules: [],
      },
      {
        name: "AWSManagedRulesKnownBadInputsRuleSet",
        overrideAction: "none",
        excludedRules: [],
      },
      {
        name: "AWSManagedRulesAnonymousIpList",
        overrideAction: "none",
        excludedRules: [],
      },
      {
        name: "AWSManagedRulesLinuxRuleSet",
        overrideAction: "none",
        excludedRules: [],
      },
      {
        name: "AWSManagedRulesSQLiRuleSet",
        overrideAction: "none",
        excludedRules: [],
      },
    ];

    managedRules.forEach((r, index) => {
      var rule: CfnWebACL.RuleProperty = WafStatements.managedRuleGroup(
        r,
        startPriorityNumber,
        index
      );

      rules.push(rule);
    });

    return rules;
  }

  public associate(resourceArn: string): void {
    if (resourceArn.includes("cloudfront")) {
      // https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_wafv2.CfnWebACLAssociation.html
      throw new Error('For Amazon CloudFront, don\'t use this resource. Instead, use your CloudFront distribution configuration.');
    }

    if (!this.webAclId) {
      throw new Error('WebAcl is not defined. Cannnot associate with resouce.');
    }

    new CfnWebACLAssociation(this, "WebAclAssociation", {
      webAclArn: this.webAclId,
      resourceArn: resourceArn,
    });
  }
}
