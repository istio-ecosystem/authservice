#include "src/common/utilities/trigger_rules.h"
#include "gtest/gtest.h"

namespace authservice {
namespace common {
namespace utilities {
namespace trigger_rules {

// Note: these tests are heavily inspired by
// https://github.com/istio/proxy/blob/master/src/envoy/http/authn/authn_utils_test.cc

TEST(TriggerRuleMatchesPath, Excluded) {
  // Trigger on everything except exactly /good-x and /allow-x
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_list;
  config::TriggerRule rule;
  rule.add_excluded_paths()->set_exact("/good-x");
  rule.add_excluded_paths()->set_exact("/allow-x");
  trigger_rules_list.Add(std::move(rule));

  EXPECT_FALSE(TriggerRuleMatchesPath("/good-x", trigger_rules_list));
  EXPECT_FALSE(TriggerRuleMatchesPath("/allow-x", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/good-1", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/allow-1", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/other", trigger_rules_list));
}

TEST(TriggerRuleMatchesPath, Included) {
  // Create a rule that triggers on everything with prefix /good and /allow.
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_list;
  config::TriggerRule rule;
  rule.add_included_paths()->set_prefix("/good");
  rule.add_included_paths()->set_prefix("/allow");
  trigger_rules_list.Add(std::move(rule));

  EXPECT_TRUE(TriggerRuleMatchesPath("/good-x", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/allow-x", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/good-2", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/allow-1", trigger_rules_list));
  EXPECT_FALSE(TriggerRuleMatchesPath("/other", trigger_rules_list));
}

TEST(TriggerRuleMatchesPath, BothIncludedAndExcluded) {
  // Trigger on prefix /good and /allow, except exactly /good-x and /allow-x
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_list;
  config::TriggerRule rule;
  rule.add_excluded_paths()->set_exact("/good-x");
  rule.add_excluded_paths()->set_exact("/allow-x");
  rule.add_included_paths()->set_prefix("/good");
  rule.add_included_paths()->set_prefix("/allow");
  trigger_rules_list.Add(std::move(rule));

  EXPECT_FALSE(TriggerRuleMatchesPath("/good-x", trigger_rules_list));
  EXPECT_FALSE(TriggerRuleMatchesPath("/allow-x", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/good-1", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/allow-1", trigger_rules_list));
  EXPECT_FALSE(TriggerRuleMatchesPath("/other", trigger_rules_list));
}

TEST(TriggerRuleMatchesPath, AlwaysTriggerWhenPathIsEmpty) {
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_list;

  // Always trigger when path is unavailable.
  EXPECT_TRUE(TriggerRuleMatchesPath("", trigger_rules_list));
}

TEST(TriggerRuleMatchesPath, AlwaysTriggerWhenNoRules) {
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_list;

  // Always trigger when there are no rules
  EXPECT_TRUE(TriggerRuleMatchesPath("/test", trigger_rules_list));
}

TEST(TriggerRuleMatchesPath, TriggerWhenAnyRuleMatches_WhenThereAreMultipleRules) {
  google::protobuf::RepeatedPtrField<config::TriggerRule> trigger_rules_list;

  // Add a rule that triggers on everything except /hello.
  config::TriggerRule rule1, rule2;
  rule1.add_excluded_paths()->set_exact("/hello");
  trigger_rules_list.Add(std::move(rule1));

  EXPECT_FALSE(TriggerRuleMatchesPath("/hello", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/other", trigger_rules_list));

  // Add another rule that triggers on path /hello.
  rule2.add_included_paths()->set_exact("/hello");
  trigger_rules_list.Add(std::move(rule2));

  EXPECT_TRUE(TriggerRuleMatchesPath("/hello", trigger_rules_list));
  EXPECT_TRUE(TriggerRuleMatchesPath("/other", trigger_rules_list));
}

TEST(MatchString, MatchString) {
  config::StringMatch match;

  EXPECT_FALSE(MatchString("", match));

  match.set_exact("exact");
  EXPECT_TRUE(MatchString("exact", match));
  EXPECT_FALSE(MatchString("exac", match));
  EXPECT_FALSE(MatchString("exacy", match));

  match.set_prefix("prefix");
  EXPECT_TRUE(MatchString("prefix-1", match));
  EXPECT_TRUE(MatchString("prefix", match));
  EXPECT_FALSE(MatchString("prefi", match));
  EXPECT_FALSE(MatchString("prefiy", match));

  match.set_suffix("suffix");
  EXPECT_TRUE(MatchString("1-suffix", match));
  EXPECT_TRUE(MatchString("suffix", match));
  EXPECT_FALSE(MatchString("suffi", match));
  EXPECT_FALSE(MatchString("suffiy", match));

  match.set_regex(".+abc.+");
  EXPECT_TRUE(MatchString("1-abc-1", match));
  EXPECT_FALSE(MatchString("1-abc", match));
  EXPECT_FALSE(MatchString("abc-1", match));
  EXPECT_FALSE(MatchString("1-ac-1", match));
}

} // namespace trigger_rules
}  // namespace utilities
}  // namespace common
}  // namespace authservice