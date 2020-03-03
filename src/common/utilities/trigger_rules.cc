#include <regex>
#include "trigger_rules.h"
#include "absl/strings/match.h"

namespace authservice {
namespace common {
namespace utilities {
namespace trigger_rules {

// Note: these functions are heavily inspired by
// https://github.com/istio/proxy/blob/master/src/envoy/http/authn/authn_utils.cc

bool MatchString(absl::string_view str, const config::StringMatch& match) {
  switch (match.match_type_case()) {
    case config::StringMatch::kExact: {
      return match.exact() == str;
    }
    case config::StringMatch::kPrefix: {
      return absl::StartsWith(str, match.prefix());
    }
    case config::StringMatch::kSuffix: {
      return absl::EndsWith(str, match.suffix());
    }
    case config::StringMatch::kRegex: {
      return std::regex_match(std::string(str), std::regex(match.regex()));
    }
    default:
      return false;
  }
}

static bool matchRule(absl::string_view path, const config::TriggerRule& rule) {
  for (const auto& excluded : rule.excluded_paths()) {
    if (MatchString(path, excluded)) {
      // The rule is not matched if any of excluded_paths matched.
      return false;
    }
  }

  if (rule.included_paths_size() > 0) {
    for (const auto& included : rule.included_paths()) {
      if (MatchString(path, included)) {
        // The rule is matched if any of included_paths matched.
        return true;
      }
    }

    // The rule is not matched if included_paths is not empty and none of them
    // matched.
    return false;
  }

  // The rule is matched if none of excluded_paths matched and included_paths is
  // empty.
  return true;
}

bool TriggerRuleMatchesPath(
    absl::string_view path,
    const google::protobuf::RepeatedPtrField<config::TriggerRule> &trigger_rules_config) {

  // If the path is empty which shouldn't happen for a HTTP request or if
  // there are no trigger rules at all, then simply return true as if there're
  // no per-path jwt support.
  if (path == "" || trigger_rules_config.size() == 0) {
    return true;
  }
  for (const auto& rule : trigger_rules_config) {
    if (matchRule(path, rule)) {
      return true;
    }
  }
  return false;
}

} // namespace trigger_rules
}  // namespace utilities
}  // namespace common
}  // namespace authservice